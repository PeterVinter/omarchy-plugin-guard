#!/usr/bin/env python3
"""Plugin Guard: static scanner for third-party Omarchy shell plugins.

Clones a plugin repository into /tmp/plugin-guard/<id>/repo and reads its
files as text. Nothing from the repository is ever executed, imported or
loaded. The only network access is `git clone` / `git fetch`.

    scanner.py scan <git-url> [--verified SHA] [--json]
    scanner.py scan-dir <folder> [--json]
    scanner.py install <scan-id> [--commit SHA] [--yes] [--json]
    scanner.py last [--json]
    scanner.py clean

The scan is heuristic. It finds the common dangerous patterns, not every
possible one, so a "safe" verdict means "nothing known was found".
"""

import argparse
import hashlib
import json
import os
import re
import resource
import shutil
import stat
import signal
import subprocess
import sys
import tempfile
import time

VERSION = "0.1.3"

HIGH, MEDIUM, INFO = "high", "medium", "info"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, INFO: 2}

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 3000
MAX_FINDINGS = 400
MAX_SNIPPET = 180
MAX_DIFF_LINES = 3000
GIT_TIMEOUT = 180
# Budget for fetching and checking out untrusted repository content. Every git
# call that writes it runs under these, so a large repository is stopped while
# it is being written, not after.
MAX_DISK_BYTES = 250_000_000      # everything one scan writes: .git and checkout
MAX_TREE_BYTES = 120_000_000      # uncompressed size of the files a checkout would write
MAX_TREE_FILES = 20_000           # entries a checkout would write
MAX_GIT_FILE_BYTES = 150_000_000  # largest single file a git process may write
GIT_CPU_SECONDS = 120             # CPU time one git process may use

DOC_EXT = {".md", ".markdown", ".txt", ".rst", ".adoc"}
DOC_NAMES = {"license", "licence", "copying", "notice", "authors", "changelog", "readme"}
ASSET_EXT = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico", ".bmp", ".avif",
    ".ttf", ".otf", ".woff", ".woff2", ".mp3", ".ogg", ".wav", ".flac", ".mp4", ".webm",
}
LANG_BY_EXT = {
    ".qml": "qml", ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js",
    ".sh": "sh", ".bash": "sh", ".zsh": "sh", ".fish": "sh",
    ".py": "py", ".lua": "lua", ".json": "json", ".jsonc": "json",
    ".rb": "other", ".pl": "other", ".desktop": "other", ".service": "other",
    ".toml": "data", ".yaml": "data", ".yml": "data", ".ini": "data", ".conf": "data", ".css": "data",
}


# ----------------------------------------------------------------- patterns

SHELLS = r"(?:ba|z|da|k|fi)?sh"

# A path that leaves the plugin's own folder.
OUTSIDE = (
    r"(?:~/|\$HOME\b|\$\{HOME\}|\$XDG_[A-Z_]+|\$\{XDG_[A-Z_]+|/home/|/etc/|/usr/|/boot/|/opt/|/var/|/root/|/srv/"
    r"|env\(\s*[\"'](?:HOME|XDG_[A-Z_]+)[\"']\s*\)|expanduser|Path\.home\(\)|environ(?:\.get\(|\[)\s*[\"'](?:HOME|XDG_[A-Z_]+)"
    r"|os\.getenv\(\s*[\"'](?:HOME|XDG_[A-Z_]+)|StandardPaths)"
)
OUTSIDE_RE = re.compile(OUTSIDE)
SYSTEM_READ_RE = re.compile(r"(?:^|[\s\"'=(:,])/(?:proc|sys|dev/(?!null|stderr|stdout|tcp|udp))/")
# Places a plugin may reasonably write besides its own folder.
SCRATCH_RE = re.compile(r"(?:/tmp/|\$XDG_RUNTIME_DIR|\$\{XDG_RUNTIME_DIR|/dev/null|/dev/std(?:err|out)|/run/user/)")
STATE_RE = re.compile(r"(?:\.cache/|\.local/state/|XDG_STATE_HOME|XDG_CACHE_HOME)")

# A credential store, keyring or browser profile is reached by a path or an
# interface, so these are high. The names of password managers and keyrings
# alone (a catalog entry, a list of secrets to mask) are not an access; they
# are a medium finding unless they appear as part of a path (see below).
SENSITIVE_RE = re.compile(
    r"(\.ssh(?![\w.])|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.gnupg\b|\.local/share/keyrings|secret-tool"
    r"|org\.freedesktop\.secrets|\.password-store|\.mozilla\b|\.thunderbird\b"
    r"|\.config/(?:chromium|google-chrome|BraveSoftware|microsoft-edge|vivaldi|opera)\b"
    r"|(?:chromium|google-chrome|BraveSoftware|Brave-Browser|microsoft-edge)/(?:Default|Profile)"
    r"|Login Data|Cookies\b(?=[\"'/ ]|$)|\.config/gh/hosts|\.aws/credentials|\.netrc\b|\.git-credentials"
    r"|/etc/shadow|wallet\.dat|\.kube/config|\.docker/config\.json|\.config/op/)"
)
SENSITIVE_NAMES = r"(?:gnome-keyring|libsecret|kwallet\w*|Bitwarden|1Password)"
# The same names as part of a path: ~/.config/Bitwarden, /usr/bin/kwalletd6, kwallet/...
SENSITIVE_NAME_PATH_RE = re.compile(r"(?:[/~]|\.config/)" + SENSITIVE_NAMES + r"(?![\w-])|(?<![\w-])" + SENSITIVE_NAMES + r"/")
SENSITIVE_NAME_RE = re.compile(r"(?<![\w-])" + SENSITIVE_NAMES + r"(?![\w-])")

URL_RE = re.compile(r"\b(?:https?|wss?|ftps?)://[^\s\"'<>)\]}`\\]+")
NET_TOOLS = r"(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|rsync|telnet|aria2c|ftp|ssh)"
NET_TOOL_SH_RE = re.compile(r"(?:^|[\s;|&(`]|\$\()(" + NET_TOOLS + r")(?=\s|$)")
NET_TOOL_STR_RE = re.compile(r"[\"'\s/]((?!ssh\b)" + NET_TOOLS + r")(?=[\"'\s]|$)")
GIT_NET_RE = re.compile(r"\bgit[\"']?[\s,]+(?:[\"']?-C[\"']?[\s,]+\S+[\s,]+)?[\"']?(clone|fetch|pull|push|ls-remote|submodule)\b")
NET_API = {
    "qml": re.compile(r"\bXMLHttpRequest\b|\bfetch\s*\(|\bWebSocket(?:Server)?\b|\bQtWebSockets\b|\bQtNetwork\b|\bQtWebEngine\b|\bQtWebView\b"),
    "py": re.compile(r"\b(?:urllib\.request|urlopen|requests\.(?:get|post|put|request|Session)|httpx\.|aiohttp\.|http\.client|socket\.socket|ftplib|smtplib|websockets?\.)"
                     r"|^\s*(?:import|from)\s+(?:urllib|requests|httpx|aiohttp|socket|http\.client|ftplib|smtplib|websockets?)\b"),
    "lua": re.compile(r"\bsocket\.(?:http|tcp|udp)|require\s*\(?\s*[\"'](?:socket|ssl|http)"),
}
NET_API["js"] = NET_API["qml"]
RAW_SOCKET_RE = re.compile(r"/dev/(?:tcp|udp)/")

PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget|fetch|aria2c)\b[^\n]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:" + SHELLS + r"|python3?|perl|ruby|node)\b"
    r"|\b" + SHELLS + r"\s+<\(\s*(?:curl|wget)\b"
    r"|\b(?:" + SHELLS + r"\s+-[a-z]*c|eval|source|\.)\s+[\"']?\$\(\s*(?:curl|wget)\b"
    r"|\bexec\s*\(\s*(?:urlopen|requests\.|urllib)"
)
SUDO_RE = re.compile(r"(?:^|[\s\"'`;|&(=\[,])(sudo|pkexec|doas|su\s+-c?)(?=[\s\"',\]]|$)")
SHELL_C_RE = re.compile(r"(?:^|[\s\"'`/;|&(\[=,])" + SHELLS + r"[\"']?\s*,?\s*[\"']?-[a-z]*c\b[\"']?\s*,?\s*(.*)$")
SHELL_VAR_RE = re.compile(r"(?<!\\)\$(?:[A-Za-z_{(@*0-9])")
INTERP_RE = re.compile(r"[\"'`]\s*\+|\+\s*[\"'`(\w]|\$\{|%s|\.format\(|\bf[\"']|\.arg\(|\.\.\s*\w|\bjoin\(")
EVAL = {
    "sh": re.compile(r"(?:^|[;&|(`]\s*|\s)eval\s+\S"),
    "qml": re.compile(r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|(?<![\w.])Function\s*\(\s*[\"'`]"),
    "py": re.compile(r"(?<![\w.])(?:eval|exec)\s*\(|\b__import__\s*\(|\bcompile\s*\([^)]*[\"']exec[\"']"),
    "lua": re.compile(r"\bloadstring\s*\(|(?<![\w.])load\s*\(|\bdofile\s*\("),
    "other": re.compile(r"(?<![\w.])eval[\s(]"),
}
EVAL["js"] = EVAL["qml"]
DYNAMIC_QML_RE = re.compile(r"\bQt\.createQmlObject\s*\(|\bQt\.createComponent\s*\(\s*(?![\"']|Qt\.resolvedUrl)")
B64_DECODE_RE = re.compile(
    r"base64\s+(?:-d|--decode|-D|-di)\b|\batob\s*\(|b64decode|decodebytes|fromBase64|openssl\s+(?:enc\s+)?-?base64\s+-d|\bxxd\s+-r"
)
EXEC_NEAR_RE = re.compile(
    r"\|\s*(?:sudo\s+)?" + SHELLS + r"\b|\beval\b|(?<![\w.])exec\s*\(|\bFunction\s*\(|\|\s*python|os\.system|subprocess|"
    + SHELLS + r"[\"']?\s*,?\s*[\"']?-[a-z]*c\b|execDetached|\bsource\s"
)
OBFUSCATION_RE = re.compile(
    r"(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\u00[0-9a-fA-F]{2}){8,}|String\.fromCharCode\s*\((?:\s*\d+\s*,){6,}"
    r"|[\"'`][A-Za-z0-9+/]{160,}={0,2}[\"'`]|\\\d{3}(?:\\\d{3}){7,}"
)
PERSIST_RE = re.compile(r"\bcrontab\b|\bsystemctl[\"']?[\s,]+(?:[\"']?--user[\"']?[\s,]+)?[\"']?(?:enable|daemon-reload)\b|\bat\s+now\b")

PROC = {
    "qml": re.compile(r"\bProcess\s*\{|\bexecDetached\s*\(|\bbar\.run\s*\(|\.run\s*\(\s*[\"'`]|\bDesktopEntry\b.*\.execute\("),
    "js": re.compile(r"\bchild_process\b|\bexecDetached\s*\(|\b(?:spawn|exec|execFile)(?:Sync)?\s*\("),
    "py": re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output|check_call|getoutput|getstatusoutput)\s*\(|\bos\.(?:system|popen|exec[lv]p?e?|spawn\w*|startfile)\s*\(|\bPopen\s*\(|\bpty\.spawn\("),
    "lua": re.compile(r"\bos\.execute\s*\(|\bio\.popen\s*\("),
}

WRITE = {
    "sh": re.compile(r"(?:^|[\s;|&(`])(?:tee|cp|mv|install|ln|rm|rmdir|chmod|chown|mkdir|touch|dd|truncate|sed\s+-i\S*|rsync|unzip|tar\s+-?x\S*)\s"),
    "py": re.compile(r"\bopen\s*\(.*,\s*[\"'][wax][bt+]*[\"']|\.write_(?:text|bytes)\s*\(|\bshutil\.(?:copy\w*|move|rmtree)\s*\(|\bos\.(?:remove|unlink|rename|replace|makedirs|mkdir|chmod|symlink|rmdir)\s*\(|\.(?:unlink|rename|mkdir|touch|symlink_to)\s*\("),
    "qml": re.compile(r"\.setText\s*\(|\bwriteAdapter\s*\(|\.saveToFile\s*\(|\bJsonAdapter\b"),
    "lua": re.compile(r"\bio\.open\s*\([^)]*,\s*[\"'][wa]|\bos\.(?:remove|rename)\s*\("),
}
WRITE["js"] = re.compile(r"\.setText\s*\(|\bwriteFile(?:Sync)?\s*\(|\bappendFile(?:Sync)?\s*\(|\bunlink(?:Sync)?\s*\(")
REDIRECT_RE = re.compile(r"(?<![0-9&>])>>?\s*[\"']?([^\s\"';|&)]+)")

BIN_ARRAY_RE = re.compile(r"(?:\bcommand\s*:|execDetached\s*\(|subprocess\.\w+\s*\(|\bPopen\s*\(|exec(?:File)?(?:Sync)?\s*\()\s*\[\s*[\"']([^\"']+)[\"']")
BIN_STRING_RE = re.compile(r"(?:os\.system|os\.popen|os\.execute|io\.popen|\.run|execDetached)\s*\(\s*f?[\"'`]\s*([\w./+-]+)")
SHELL_C_LITERAL_RE = re.compile(SHELLS + r"[\"']?\s*,?\s*[\"']?-[a-z]*c[\"']?\s*,?\s*[\"'`](.+)")

SH_KEYWORDS = set("""
if then else elif fi for while until do done case esac in function select time coproc return exit break continue
echo printf read cd pwd export unset local declare typeset readonly set shift test true false source eval exec trap
wait let alias unalias type command builtin hash kill jobs fg bg umask getopts shopt mapfile readarray pushd popd
dirs disown enable help history logout suspend times ulimit caller compgen complete compopt bind fc
""".split())

RULE_TITLES = {
    "pipe-to-shell": "Downloads and runs a remote script",
    "eval": "Evaluates code from a string",
    "privilege-escalation": "Asks for root (sudo, pkexec, doas)",
    "shell-c-vars": "Shell -c with interpolated input",
    "base64-exec": "Base64 decode next to code execution",
    "write-outside": "Writes outside its own plugin folder",
    "sensitive-path": "Touches credentials, keyrings or browser profiles",
    "sensitive-name": "Names a password manager or keyring",
    "raw-socket": "Raw /dev/tcp socket (reverse-shell idiom)",
    "persistence": "Installs itself to run later (cron, systemd)",
    "network-url": "Contains a network URL",
    "network-api": "Makes network requests",
    "network-tool": "Calls a network tool",
    "process-exec": "Starts external processes",
    "shell-c": "Runs a shell -c command",
    "path-outside": "Reads paths outside its own folder",
    "file-write": "Writes files (target not resolved)",
    "state-write": "Writes to cache or state folders",
    "base64-decode": "Decodes base64 data",
    "dynamic-qml": "Builds QML from a string at runtime",
    "obfuscation": "Looks obfuscated or encoded",
    "opaque-binary": "Binary file that cannot be reviewed",
    "symlink": "Symbolic link in the repository",
    "submodule": "Pulls in git submodules",
    "manifest-problem": "Manifest problem",
    "insecure-transport": "Cloned over an unencrypted or unauthenticated transport",
    "external-binary": "Calls an external program",
    "manifest": "Manifest declaration",
    "inventory": "File inventory",
    "truncated": "Large file only partly scanned",
}

# rule -> rules on the same line that make it redundant
SUPPRESSED_BY = {
    "path-outside": {"write-outside", "sensitive-path", "state-write"},
    "file-write": {"write-outside", "state-write"},
    "shell-c": {"shell-c-vars", "pipe-to-shell", "base64-exec"},
    "network-tool": {"pipe-to-shell"},
    "network-url": {"pipe-to-shell"},
    "base64-decode": {"base64-exec"},
    "process-exec": {"shell-c-vars", "shell-c", "pipe-to-shell"},
}


class GuardError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


# ------------------------------------------------------------------ helpers

def state_dir():
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    path = os.path.join(base, "plugin-guard")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def work_root():
    """/tmp/plugin-guard, private to this user. /tmp is shared, so refuse a
    directory someone else could have planted."""
    root = os.environ.get("PLUGIN_GUARD_TMP") or "/tmp/plugin-guard"
    try:
        os.mkdir(root, 0o700)
    except FileExistsError:
        pass
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise GuardError("unsafe-tmp", f"{root} is not a directory owned by you; remove it and retry")
    os.chmod(root, 0o700)
    return root


def progress(stage):
    print(f"stage:{stage}", file=sys.stderr, flush=True)


def write_json_atomic(path, data):
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False)
    os.replace(tmp, path)


def clean_text(value, limit=MAX_SNIPPET):
    """One printable line, safe to show: no control characters."""
    text = "".join(ch if ch.isprintable() else " " for ch in str(value))
    return text[:limit]


ALLOWED_SCHEMES = {"https", "http", "ssh", "git", "git+ssh", "ssh+git", "file"}


def validate_url(url):
    """Same rules as omarchy-git-url-check, plus a few sanity limits."""
    if not url or not url.strip():
        raise GuardError("invalid-url", "Enter a git URL, for example https://github.com/user/plugin.git")
    if url != url.strip() or len(url) > 2000 or any(ch.isspace() or not ch.isprintable() for ch in url):
        raise GuardError("invalid-url", "The URL contains spaces or control characters")
    if url.startswith("-"):
        raise GuardError("invalid-url", "The URL looks like a git option, not a repository")
    if re.match(r"^[A-Za-z0-9][A-Za-z0-9+.-]*::", url):
        raise GuardError("invalid-url", "The URL names a git transport helper, not a repository")
    scheme = re.match(r"^([A-Za-z0-9][A-Za-z0-9+.-]*)://(.*)$", url)
    if scheme:
        if scheme.group(1).lower() not in ALLOWED_SCHEMES:
            raise GuardError("invalid-url", f"'{scheme.group(1)}' is not a transport Omarchy clones from")
        if not scheme.group(2).strip("/"):
            raise GuardError("invalid-url", "The URL has no host or path")
        return
    if re.match(r"^[\w.-]+@[\w.-]+:[\w./~-]+$", url):  # scp-style ssh
        return
    if os.path.isdir(url):  # local repository
        return
    raise GuardError("invalid-url", "Not a git URL. Expected https://…, ssh://…, user@host:path or a local folder")


def scan_id_for(url):
    tail = re.sub(r"\.git$", "", url.rstrip("/").split("/")[-1].split(":")[-1])
    slug = re.sub(r"[^a-z0-9._-]+", "-", tail.lower()).strip("-.")[:40] or "plugin"
    return f"{slug}-{hashlib.sha1(url.encode()).hexdigest()[:8]}"


def disk_usage(path):
    """Bytes actually allocated under path (blocks, so sparse files count as written)."""
    total = 0
    stack = [path]
    while stack:
        try:
            with os.scandir(stack.pop()) as entries:
                for entry in entries:
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    total += info.st_blocks * 512
                    if stat.S_ISDIR(info.st_mode):
                        stack.append(entry.path)
        except OSError:
            continue
    return total


def git_limits():
    """Runs in the child before git starts: no core dumps, bounded CPU time and file size."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (GIT_CPU_SECONDS, GIT_CPU_SECONDS + 10))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_GIT_FILE_BYTES, MAX_GIT_FILE_BYTES))


def git(args, cwd=None, timeout=GIT_TIMEOUT, check=True, budget_dir=None):
    """Run git. With budget_dir, git runs in its own process group under CPU and
    file-size limits, and is killed as soon as budget_dir holds more than
    MAX_DISK_BYTES, so the budget applies while the repository is written."""
    env = dict(os.environ)
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_SSH_COMMAND": env.get("GIT_SSH_COMMAND", "ssh -oBatchMode=yes"),
        "GIT_ASKPASS": "true",
        "LC_ALL": "C",
    })
    base = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never",
            "-c", "core.fsmonitor=false", "-c", "advice.detachedHead=false"]
    out_file = tempfile.TemporaryFile()
    err_file = tempfile.TemporaryFile()
    try:
        try:
            process = subprocess.Popen(base + args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=out_file, stderr=err_file,
                                       start_new_session=True, preexec_fn=git_limits if budget_dir else None)
        except FileNotFoundError:
            raise GuardError("git-missing", "git is not installed")
        deadline = time.monotonic() + timeout
        stopped = None
        while process.poll() is None:
            if time.monotonic() > deadline:
                stopped = GuardError("git-timeout", f"git {args[0]} timed out after {timeout}s")
            elif budget_dir and disk_usage(budget_dir) > MAX_DISK_BYTES:
                stopped = GuardError("too-large", f"The repository is larger than {MAX_DISK_BYTES // 1_000_000} MB, so it was not fetched")
            if stopped:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                process.wait()
                raise stopped
            time.sleep(0.1)
        try:
            os.killpg(process.pid, signal.SIGKILL)  # anything git left behind
        except OSError:
            pass
        out_file.seek(0)
        err_file.seek(0)
        out = out_file.read().decode("utf-8", "replace")
        err = err_file.read().decode("utf-8", "replace")
    finally:
        out_file.close()
        err_file.close()
    if check and process.returncode != 0:
        if process.returncode in (-signal.SIGXFSZ, -signal.SIGXCPU):
            raise GuardError("too-large", "git hit its file-size or CPU limit, so the repository was not fetched")
        raise GuardError("git-failed", clean_text(err.strip().splitlines()[-1] if err.strip() else "git failed", 300))
    return process.returncode, out, err


def check_tree_budget(repo):
    """Before anything is checked out: size up the files the checkout would
    write, from the tree objects alone, and refuse a tree over the budget."""
    _, listing, _ = git(["ls-tree", "-r", "-l", "-z", "HEAD"], cwd=repo)
    files = 0
    size = 0
    for entry in listing.split("\0"):
        if not entry:
            continue
        files += 1
        fields = entry.split("\t", 1)[0].split()
        if len(fields) >= 4 and fields[3].isdigit():
            size += int(fields[3])
        if files > MAX_TREE_FILES or size > MAX_TREE_BYTES:
            raise GuardError("too-large", f"The repository holds more than {MAX_TREE_FILES} files or {MAX_TREE_BYTES // 1_000_000} MB of files, so it was not checked out")


# ------------------------------------------------------------------ scanner

def classify(path, head):
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    if ext in ASSET_EXT:
        return "asset"
    if ext in DOC_EXT or name.split(".")[0] in DOC_NAMES:
        return "doc"
    if b"\0" in head[:4096]:
        return "binary"
    if ext in LANG_BY_EXT:
        return LANG_BY_EXT[ext]
    first = head[:160].split(b"\n", 1)[0].decode("utf-8", "replace")
    if first.startswith("#!"):
        if re.search(r"\b(?:ba|z|da|k|fi)?sh\b", first):
            return "sh"
        if "python" in first:
            return "py"
        if "lua" in first:
            return "lua"
        if "node" in first:
            return "js"
        return "other"
    return "data" if name.startswith(".") else "other"


TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs"}
TEST_NAME_RE = re.compile(r"^test[_.-]|[._-](?:test|spec)\.[\w.]+$")


def is_test_path(rel):
    parts = rel.lower().split("/")
    return any(part in TEST_DIRS for part in parts[:-1]) or bool(TEST_NAME_RE.search(parts[-1]))


def without_comment_lines(text, lang):
    """Drops whole-line comments, as scan_text does, so a name in a comment is
    not taken for a use. Block comments are kept: that errs toward keeping a
    finding high."""
    prefix = {"js": "//", "qml": "//", "sh": "#", "py": "#", "other": "#", "lua": "--"}.get(lang)
    if prefix is None:
        return text
    keep = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith(prefix) and not stripped.startswith("#!"):
            continue
        keep.append(line)
    return "\n".join(keep)


def reference_patterns(rel):
    """Ways a file's name or folder can appear in the code that loads or runs it:
    its file name as a word, or the path of a folder above it as a path (test/ or
    "test", not the plain word test)."""
    parts = rel.split("/")
    file_name = re.escape(parts[-1])
    folders = "|".join(re.escape("/".join(parts[:end])) for end in range(1, len(parts)))
    pattern = r"(?<![\w-])" + file_name + r"(?![\w-])"
    if folders:
        pattern += r"|(?<![\w-])(?:" + folders + r")(?:/|(?=[\"'`]))"
    return re.compile(pattern)


class Scan:
    def __init__(self, root, plugin_id=""):
        self.root = root
        self.plugin_id = plugin_id
        self.findings = []
        self.binaries = {}
        self.own_files = set()
        self.counts_by_kind = {}
        self.code_files = []
        self.seen = set()

    def add(self, severity, rule, file="", line=0, snippet="", match=None, detail=""):
        key = (rule, file, line, detail if (not line or severity == INFO) else "")
        if key in self.seen:
            return
        self.seen.add(key)
        snippet = snippet.rstrip("\n")
        start = end = 0
        if match is not None:
            start, end = match
        # Keep the matched part visible when the line is long.
        lead = len(snippet) - len(snippet.lstrip())
        offset = lead
        if end - lead > MAX_SNIPPET:
            offset = max(lead, start - 40)
        shown = clean_text(snippet[offset:], MAX_SNIPPET)
        start = max(0, min(len(shown), start - offset))
        end = max(start, min(len(shown), end - offset))
        self.findings.append({
            "severity": severity, "rule": rule, "title": RULE_TITLES.get(rule, rule),
            "file": clean_text(file, 200), "line": line, "snippet": shown,
            "matchStart": start, "matchEnd": end, "detail": clean_text(detail, 240), "new": False,
        })

    def own_path(self, text):
        return bool(self.plugin_id) and f"omarchy/plugins/{self.plugin_id}" in text

    def note_binary(self, name, file, line):
        name = name.strip()
        if not name or not re.match(r"^[\w./+~-]+$", name) or name in SH_KEYWORDS or len(name) > 80:
            return
        if name.startswith("-") or name.isdigit():
            return
        entry = self.binaries.setdefault(name, {"name": name, "file": file, "line": line, "count": 0})
        entry["count"] += 1

    # -- one file -----------------------------------------------------------

    def scan_text(self, rel, lang, text):
        lines = text.split("\n")
        rules = "qml" if lang == "js" and rel.endswith(".qml") else lang
        in_block = False
        functions = set(re.findall(r"^\s*(?:function\s+)?([A-Za-z_][\w-]*)\s*\(\)\s*\{?", text, re.M)) if lang == "sh" else set()
        continued = False
        heredoc = None
        per_line = {}

        def hit(severity, rule, number, raw, match=None, detail=""):
            per_line.setdefault(number, []).append((severity, rule, raw, match, detail))

        for number, raw in enumerate(lines, 1):
            line = raw
            stripped = line.strip()
            if not stripped:
                continued = False
                continue
            if len(raw) > 1200 and lang != "json":
                hit(MEDIUM, "obfuscation", number, raw, (0, 0), f"line is {len(raw)} characters long")
            # Comments are not code. Keep shebangs.
            if lang in ("qml", "js"):
                if in_block:
                    if "*/" in line:
                        in_block = False
                    continue
                if stripped.startswith("/*") and "*/" not in stripped:
                    in_block = True
                    continue
                if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                    continue
            elif lang in ("sh", "py", "other", "data") and stripped.startswith("#"):
                continue
            elif lang == "lua" and stripped.startswith("--"):
                continue

            if lang == "json":
                for found in URL_RE.finditer(line):
                    hit(INFO if rel == "manifest.json" else MEDIUM, "network-url", number, raw, found.span())
                continue
            if lang == "data":
                continue

            self.scan_line(rel, lang, rules, number, raw, hit)

            if lang == "sh":
                if heredoc:
                    if stripped == heredoc:
                        heredoc = None
                elif not continued:
                    opened = re.search(r"<<-?\s*[\"']?([A-Za-z_]\w*)[\"']?", line)
                    self.shell_binaries(rel, number, line, functions)
                    if opened:
                        heredoc = opened.group(1)
                continued = stripped.endswith("\\")

        # base64 decode with execution on the same or a nearby line
        for number, raw in enumerate(lines, 1):
            decode = B64_DECODE_RE.search(raw)
            if not decode or lang in ("json", "data"):
                continue
            window = lines[max(0, number - 3):number + 2]
            if any(EXEC_NEAR_RE.search(near) for near in window):
                hit(HIGH, "base64-exec", number, raw, decode.span())
            else:
                hit(MEDIUM, "base64-decode", number, raw, decode.span())

        for number in sorted(per_line):
            present = {rule for _, rule, _, _, _ in per_line[number]}
            for severity, rule, raw, match, detail in per_line[number]:
                if SUPPRESSED_BY.get(rule, set()) & present:
                    continue
                self.add(severity, rule, rel, number, raw, match, detail)

    def scan_line(self, rel, lang, rules, number, raw, hit):
        line = raw

        found = PIPE_TO_SHELL_RE.search(line)
        if found:
            hit(HIGH, "pipe-to-shell", number, raw, found.span())

        found = RAW_SOCKET_RE.search(line)
        if found:
            hit(HIGH, "raw-socket", number, raw, found.span())

        pattern = EVAL.get(rules)
        found = pattern.search(line) if pattern else None
        if found:
            hit(HIGH, "eval", number, raw, found.span())

        found = SUDO_RE.search(line)
        if found:
            hit(HIGH, "privilege-escalation", number, raw, found.span(1))

        found = SHELL_C_RE.search(line)
        if found:
            rest = found.group(1)
            literal_only = bool(re.match(r"^[\"'`][^\"'`]*[\"'`]\s*[\])},;]*\s*$", rest))
            if lang == "sh":
                variable = bool(SHELL_VAR_RE.search(rest))
            else:
                variable = bool(INTERP_RE.search(rest)) or bool(re.search(r"\bf[\"']|`[^`]*\$\{", line)) or (rest.strip() != "" and not literal_only and not rest.lstrip().startswith(("\"", "'", "`")))
            hit(HIGH if variable else MEDIUM, "shell-c-vars" if variable else "shell-c", number, raw, found.span())
            literal = SHELL_C_LITERAL_RE.search(line)
            if literal and lang != "sh":
                for segment in re.split(r"\|\||&&|[|;]|\$\(", literal.group(1)):
                    words = segment.strip().split()
                    while words and re.match(r"^\w+=", words[0]):
                        words.pop(0)
                    if words:
                        self.note_binary(words[0].strip("\"'`()"), rel, number)

        found = SENSITIVE_RE.search(line) or SENSITIVE_NAME_PATH_RE.search(line)
        if found:
            hit(HIGH, "sensitive-path", number, raw, found.span())
        else:
            found = SENSITIVE_NAME_RE.search(line)
            if found:
                hit(MEDIUM, "sensitive-name", number, raw, found.span())

        found = PERSIST_RE.search(line)
        if found:
            hit(HIGH, "persistence", number, raw, found.span())

        self.scan_writes(lang, rules, number, raw, hit)

        for found in URL_RE.finditer(line):
            hit(MEDIUM, "network-url", number, raw, found.span())
        pattern = NET_API.get(rules)
        found = pattern.search(line) if pattern else None
        if found:
            hit(MEDIUM, "network-api", number, raw, found.span())
        found = (NET_TOOL_SH_RE if lang == "sh" else NET_TOOL_STR_RE).search(line)
        if found:
            hit(MEDIUM, "network-tool", number, raw, found.span(1))
        found = GIT_NET_RE.search(line)
        if found:
            hit(MEDIUM, "network-tool", number, raw, found.span())

        pattern = PROC.get(rules)
        found = pattern.search(line) if pattern else None
        if found:
            hit(MEDIUM, "process-exec", number, raw, found.span())

        found = DYNAMIC_QML_RE.search(line) if rules in ("qml", "js") else None
        if found:
            hit(MEDIUM, "dynamic-qml", number, raw, found.span())

        found = OBFUSCATION_RE.search(line)
        if found:
            hit(MEDIUM, "obfuscation", number, raw, (found.start(), min(found.end(), found.start() + 60)))

        found = OUTSIDE_RE.search(line) or SYSTEM_READ_RE.search(line)
        if found and not self.own_path(line):
            hit(MEDIUM, "path-outside", number, raw, found.span())

        if lang != "sh":
            for found in BIN_ARRAY_RE.finditer(line):
                self.note_binary(found.group(1), rel, number)
            for found in BIN_STRING_RE.finditer(line):
                self.note_binary(found.group(1), rel, number)

    def scan_writes(self, lang, rules, number, raw, hit):
        line = raw
        targets = []
        if lang == "sh":
            for found in REDIRECT_RE.finditer(line):
                targets.append((found.group(1), found.span()))
        pattern = WRITE.get(rules)
        op = pattern.search(line) if pattern else None
        if op:
            targets.append((line[op.start():], op.span()))
        for target, span in targets:
            if target.startswith("&") or SCRATCH_RE.match(target.lstrip("\"'")):
                continue
            outside = OUTSIDE_RE.search(target)
            if outside and not self.own_path(target):
                if STATE_RE.search(target):
                    hit(MEDIUM, "state-write", number, raw, span)
                elif SCRATCH_RE.search(target) and not re.search(r"(?:~/|\$HOME|/etc/|/usr/|/home/)", target):
                    continue
                else:
                    hit(HIGH, "write-outside", number, raw, span)
            elif op and span == op.span() and rules != "sh" and not SCRATCH_RE.search(target):
                hit(MEDIUM, "file-write", number, raw, span)

    def shell_binaries(self, rel, number, line, functions):
        code = re.sub(r"\"(?:\\.|[^\"\\])*\"|'[^']*'", " S ", line)
        code = code.split(" #", 1)[0]
        for segment in re.split(r"\|\||&&|[|;]|\$\(|`|\bthen\b|\bdo\b|\belse\b|\{|\(", code):
            words = segment.strip().split()
            while words and (re.match(r"^[A-Za-z_]\w*\+?=", words[0]) or words[0] in ("!", "time", "exec", "command", "env", "nohup", "setsid", "sudo", "if", "elif", "while", "until")):
                words.pop(0)
            if not words:
                continue
            name = words[0]
            if name in SH_KEYWORDS or name in functions or name == "S" or name.endswith(")"):
                continue
            if re.match(r"^[A-Za-z0-9_][\w.+-]*$|^[./~][\w./+-]*$", name):
                self.note_binary(name, rel, number)

    # -- whole tree ---------------------------------------------------------

    def walk(self):
        files = []
        for base, dirs, names in os.walk(self.root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d != ".git")
            for name in sorted(names):
                files.append(os.path.join(base, name))
            for name in list(dirs):
                full = os.path.join(base, name)
                if os.path.islink(full):
                    files.append(full)
                    dirs.remove(name)
        return files[:MAX_FILES], len(files)

    def run(self):
        files, total = self.walk()
        self.own_files = {os.path.relpath(path, self.root) for path in files}
        for path in files:
            rel = os.path.relpath(path, self.root)
            if os.path.islink(path):
                try:
                    target = os.readlink(path)
                except OSError:
                    target = "?"
                self.add(MEDIUM, "symlink", rel, 0, f"{rel} -> {target}", (0, 0))
                self.bump("symlink")
                continue
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as handle:
                    data = handle.read(MAX_FILE_BYTES + 1)
            except OSError:
                continue
            kind = classify(rel, data)
            self.bump(kind)
            if kind not in ("asset", "doc", "binary"):
                self.code_files.append((rel, kind))
            if rel == ".gitmodules":
                self.add(MEDIUM, "submodule", rel, 0, "repository declares git submodules", (0, 0))
            if kind in ("asset", "doc"):
                continue
            if kind == "binary":
                label = "ELF executable" if data[:4] == b"\x7fELF" else "binary data"
                self.add(MEDIUM, "opaque-binary", rel, 0, f"{rel}: {label}, {len(data)} bytes", (0, 0))
                continue
            if len(data) > MAX_FILE_BYTES:
                data = data[:MAX_FILE_BYTES]
                self.add(INFO, "truncated", rel, 0, f"only the first {MAX_FILE_BYTES // 1000} kB were scanned", (0, 0))
            self.scan_text(rel, kind, data.decode("utf-8", "replace"))
        if total > MAX_FILES:
            self.add(MEDIUM, "obfuscation", "", 0, f"{total} files; only the first {MAX_FILES} were scanned", (0, 0), detail="too-many-files")
        return self

    def demote_unreferenced_test_evals(self):
        """`eval` or `new Function` in a test file that no other file of the plugin
        names is never run by the plugin: medium, not high. Only this rule, only
        when the file's name and its folders appear nowhere in the plugin's code
        (a test file loaded from Service.qml, a Process command or a script keeps
        its severity). Everything else in a test file is judged as usual."""
        candidates = [f for f in self.findings
                      if f["rule"] == "eval" and f["severity"] == HIGH and len(f["file"]) < 200 and is_test_path(f["file"])]
        if not candidates:
            return
        patterns = {f["file"]: reference_patterns(f["file"]) for f in candidates}
        referenced = set()
        for rel, kind in self.code_files:
            if len(referenced) == len(patterns):
                break
            if is_test_path(rel):
                continue
            try:
                with open(os.path.join(self.root, rel), "rb") as handle:
                    text = handle.read(MAX_FILE_BYTES + 1).decode("utf-8", "replace")
            except OSError:
                continue
            text = without_comment_lines(text, "qml" if rel.endswith(".qml") else kind)
            for target, pattern in patterns.items():
                if target not in referenced and pattern.search(text):
                    referenced.add(target)
        for finding in candidates:
            if finding["file"] not in referenced:
                finding["severity"] = MEDIUM
                finding["title"] = RULE_TITLES["eval"] + " (in a test file the plugin never references)"

    def bump(self, kind):
        self.counts_by_kind[kind] = self.counts_by_kind.get(kind, 0) + 1


def read_manifest(root):
    path = os.path.join(root, "manifest.json")
    if os.path.islink(path) or not os.path.isfile(path):
        return None, "manifest.json is missing, so this is not an Omarchy plugin"
    try:
        with open(path, "rb") as handle:
            manifest = json.loads(handle.read(200_000).decode("utf-8", "replace"))
    except (OSError, ValueError) as error:
        return None, f"manifest.json is not valid JSON ({clean_text(error, 80)})"
    if not isinstance(manifest, dict):
        return None, "manifest.json is not a JSON object"
    return manifest, ""


def manifest_findings(scan, manifest, problem):
    if manifest is None:
        scan.add(MEDIUM, "manifest-problem", "manifest.json", 0, problem, (0, 0), detail="missing")
        return {}

    def text(key):
        return clean_text(manifest.get(key, ""), 120) if isinstance(manifest.get(key, ""), (str, int, float)) else ""

    info = {key: text(key) for key in ("id", "name", "version", "author", "license", "description")}
    kinds = [clean_text(k, 40) for k in manifest.get("kinds", []) if isinstance(k, str)] if isinstance(manifest.get("kinds"), list) else []
    entries = manifest.get("entryPoints") if isinstance(manifest.get("entryPoints"), dict) else {}
    info["kinds"] = kinds
    info["entryPoints"] = {clean_text(k, 40): clean_text(v, 120) for k, v in entries.items() if isinstance(v, str)}

    scan.add(INFO, "manifest", "manifest.json", 0,
             f"{info['name'] or '?'} {info['version'] or '?'} by {info['author'] or 'unknown'} (id {info['id'] or '?'})", (0, 0), detail="identity")
    scan.add(INFO, "manifest", "manifest.json", 0, "kinds: " + (", ".join(kinds) or "none"), (0, 0), detail="kinds")
    if info["entryPoints"]:
        scan.add(INFO, "manifest", "manifest.json", 0,
                 "entry points: " + ", ".join(f"{k} = {v}" for k, v in info["entryPoints"].items()), (0, 0), detail="entries")

    if manifest.get("schemaVersion") != 1:
        scan.add(MEDIUM, "manifest-problem", "manifest.json", 0, "schemaVersion is not 1", (0, 0), detail="schema")
    plugin_id = info["id"]
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", plugin_id) or ".." in plugin_id:
        scan.add(MEDIUM, "manifest-problem", "manifest.json", 0, f"invalid plugin id '{plugin_id}'", (0, 0), detail="id")
    elif plugin_id.startswith("omarchy."):
        scan.add(MEDIUM, "manifest-problem", "manifest.json", 0, f"id '{plugin_id}' uses the reserved omarchy.* namespace", (0, 0), detail="reserved")
    if "service" in kinds:
        scan.add(INFO, "manifest", "manifest.json", 0, "runs as a background service as soon as it is enabled", (0, 0), detail="service")
    for key, value in info["entryPoints"].items():
        unsafe = value.startswith("/") or ".." in value.split("/")
        target = os.path.join(scan.root, value)
        if unsafe:
            scan.add(MEDIUM, "manifest-problem", "manifest.json", 0, f"entry point {key} = {value} leaves the plugin folder", (0, 0), detail="ep-" + key)
        elif not os.path.isfile(target) or os.path.islink(target):
            scan.add(MEDIUM, "manifest-problem", "manifest.json", 0, f"entry point {key} = {value} does not exist", (0, 0), detail="ep-" + key)
    return info


def verdict_for(counts):
    high, medium = counts[HIGH], counts[MEDIUM]
    if high:
        return "danger", min(100, 70 + 10 * (high - 1))
    if medium:
        return "caution", min(69, 20 + 3 * (medium - 1))
    return "safe", 0


def summarize(findings, counts, verdict):
    def top(severity, limit=3):
        seen = []
        for finding in findings:
            if finding["severity"] == severity and finding["title"] not in seen:
                seen.append(finding["title"])
        extra = len(seen) - limit
        text = "; ".join(seen[:limit])
        return text + (f"; +{extra} more kinds" if extra > 0 else "")

    if verdict == "danger":
        return f"{counts[HIGH]} high-risk pattern{'s' if counts[HIGH] != 1 else ''}: {top(HIGH)}. Do not install without reading the code."
    if verdict == "caution":
        return f"No high-risk patterns, but {counts[MEDIUM]} thing{'s' if counts[MEDIUM] != 1 else ''} to review: {top(MEDIUM)}."
    return "No risky patterns found. This is a heuristic check, not a guarantee."


def scan_tree(root):
    manifest, problem = read_manifest(root)
    plugin_id = manifest.get("id", "") if isinstance(manifest, dict) and isinstance(manifest.get("id"), str) else ""
    scan = Scan(root, plugin_id if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", plugin_id or "") else "")
    info = manifest_findings(scan, manifest, problem)
    scan.run()
    scan.demote_unreferenced_test_evals()

    for entry in sorted(scan.binaries.values(), key=lambda e: e["name"]):
        name = entry["name"]
        own = name.lstrip("./") in scan.own_files or os.path.basename(name) in {os.path.basename(f) for f in scan.own_files}
        entry["own"] = own
        scan.add(INFO, "external-binary", entry["file"], entry["line"],
                 f"{name}" + (" (script shipped with the plugin)" if own else "") + (f"  ×{entry['count']}" if entry["count"] > 1 else ""),
                 (0, len(name)), detail=name)
    kinds = ", ".join(f"{count} {kind}" for kind, count in sorted(scan.counts_by_kind.items(), key=lambda kv: -kv[1]))
    scan.add(INFO, "inventory", "", 0, f"{sum(scan.counts_by_kind.values())} files: {kinds}", (0, 0), detail="inventory")
    skipped = scan.counts_by_kind.get("doc", 0) + scan.counts_by_kind.get("asset", 0)
    if skipped:
        scan.add(INFO, "inventory", "", 0, f"{skipped} documentation or asset file{'s' if skipped != 1 else ''} not scanned for code patterns", (0, 0), detail="skipped")

    findings = sorted(scan.findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["rule"], f["file"], f["line"]))
    counts = {level: sum(1 for f in findings if f["severity"] == level) for level in (HIGH, MEDIUM, INFO)}
    verdict, score = verdict_for(counts)
    return {
        "verdict": verdict, "score": score, "counts": counts,
        "summary": summarize(findings, counts, verdict),
        "manifest": info, "pluginId": info.get("id", "") if info else "",
        "files": sum(scan.counts_by_kind.values()),
        "binaries": sorted(scan.binaries.values(), key=lambda e: e["name"]),
        "findings": findings[:MAX_FINDINGS], "findingsTotal": len(findings),
    }


# --------------------------------------------------------------------- diff

def diff_since(repo, sha, head, result):
    code, _, _ = git(["cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo, check=False)
    if code != 0:
        progress("fetching")
        git(["fetch", "--quiet", "origin", sha], cwd=repo, check=False)
        code, _, _ = git(["cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo, check=False)
    if code != 0:
        return {"ok": False, "sha": sha, "error": f"Commit {sha[:12]} does not exist in this repository"}
    full = git(["rev-parse", f"{sha}^{{commit}}"], cwd=repo)[1].strip()
    ancestor = git(["merge-base", "--is-ancestor", full, head], cwd=repo, check=False)[0] == 0
    commits = int(git(["rev-list", "--count", f"{full}..{head}"], cwd=repo)[1].strip() or 0)
    common = ["--no-color", "--no-ext-diff", "--no-textconv", "--no-renames"]
    numstat = git(["diff", "--numstat", "-z"] + common + [full, head], cwd=repo)[1]
    files, insertions, deletions = [], 0, 0
    for row in numstat.split("\0"):
        parts = row.split("\t")
        if len(parts) != 3:
            continue
        added = int(parts[0]) if parts[0].isdigit() else 0
        removed = int(parts[1]) if parts[1].isdigit() else 0
        insertions += added
        deletions += removed
        files.append({"path": clean_text(parts[2], 200), "added": added, "removed": removed, "binary": parts[0] == "-"})
    text = git(["diff", "-U3"] + common + [full, head], cwd=repo)[1]

    # Which lines of HEAD are new since the verified commit.
    added_lines, current, number = {}, None, 0
    for line in text.split("\n"):
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("@@"):
            hunk = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
            number = int(hunk.group(1)) if hunk else 0
        elif current is not None and line.startswith("+") and not line.startswith("+++"):
            added_lines.setdefault(current, set()).add(number)
            number += 1
        elif line.startswith(" "):
            number += 1
    new_counts = {HIGH: 0, MEDIUM: 0, INFO: 0}
    for finding in result["findings"]:
        if finding["line"] and finding["line"] in added_lines.get(finding["file"], ()):
            finding["new"] = True
            new_counts[finding["severity"]] += 1

    lines = text.split("\n")
    shown = [clean_text(line.replace("\t", "    "), 400) for line in lines[:MAX_DIFF_LINES]]
    code_files = [f["path"] for f in files if os.path.splitext(f["path"])[1].lower() not in DOC_EXT | ASSET_EXT]
    if head == full:
        summary = "HEAD is the verified commit. Nothing has changed."
    else:
        summary = (f"{commits} commit{'s' if commits != 1 else ''} since {full[:7]}: {len(files)} file{'s' if len(files) != 1 else ''} changed, "
                   f"+{insertions} −{deletions}. {len(code_files)} of them {'is' if len(code_files) == 1 else 'are'} code.")
        if new_counts[HIGH] or new_counts[MEDIUM]:
            summary += f" The new lines add {new_counts[HIGH]} high and {new_counts[MEDIUM]} medium findings."
        else:
            summary += " The new lines add no high or medium findings."
        if not ancestor:
            summary += " Warning: the verified commit is not an ancestor of HEAD, so history was rewritten."
    return {
        "ok": True, "sha": full, "identical": head == full, "ancestor": ancestor, "commits": commits,
        "files": files[:200], "filesChanged": len(files), "insertions": insertions, "deletions": deletions,
        "newHigh": new_counts[HIGH], "newMedium": new_counts[MEDIUM],
        "summary": summary, "lines": shown, "totalLines": len(lines), "truncated": len(lines) > MAX_DIFF_LINES,
    }


# ----------------------------------------------------------------- commands

def do_scan(url, verified=""):
    validate_url(url)
    verified = (verified or "").strip()
    if verified and not re.match(r"^[0-9a-fA-F]{7,64}$", verified):
        raise GuardError("invalid-sha", "The verified commit must be a hex SHA of 7 to 64 characters")
    scan_id = scan_id_for(url)
    base = os.path.join(work_root(), scan_id)
    shutil.rmtree(base, ignore_errors=True)
    os.makedirs(base, mode=0o700)
    repo = os.path.join(base, "repo")

    progress("cloning")
    try:
        # No checkout yet: the budget is checked on the tree before any file is written.
        git(["clone", "--quiet", "--no-checkout", "--no-recurse-submodules", "--", url, repo], budget_dir=base)
        check_tree_budget(repo)
        git(["checkout", "--quiet", "--detach", "HEAD"], cwd=repo, budget_dir=base)
    except GuardError as error:
        shutil.rmtree(base, ignore_errors=True)
        raise GuardError("too-large" if error.code == "too-large" else "clone-failed", error.message)
    head = git(["rev-parse", "HEAD"], cwd=repo)[1].strip()
    subject = git(["log", "-1", "--format=%s"], cwd=repo)[1].strip()
    date = git(["log", "-1", "--format=%cI"], cwd=repo)[1].strip()

    progress("scanning")
    result = scan_tree(repo)
    if re.match(r"^(?:http|git)://", url):
        result["findings"].insert(result["counts"][HIGH], {
            "severity": MEDIUM, "rule": "insecure-transport", "title": RULE_TITLES["insecure-transport"], "file": "", "line": 0,
            "snippet": clean_text(url), "matchStart": 0, "matchEnd": 0, "detail": "", "new": False})
        result["counts"][MEDIUM] += 1
        result["verdict"], result["score"] = verdict_for(result["counts"])
        result["summary"] = summarize(result["findings"], result["counts"], result["verdict"])

    diff = None
    if verified:
        progress("diffing")
        diff = diff_since(repo, verified.lower(), head, result)

    result.update({
        "ok": True, "version": VERSION, "id": scan_id, "url": url, "dir": repo,
        "head": head, "headSubject": clean_text(subject, 120), "headDate": clean_text(date, 40),
        "scannedAt": int(time.time()), "verified": diff["sha"] if diff and diff.get("ok") else "", "diff": diff,
    })
    write_json_atomic(os.path.join(base, "scan.json"), {k: result[k] for k in ("id", "url", "head", "verified", "pluginId", "verdict")})
    return result


def do_scan_dir(folder):
    if not os.path.isdir(folder):
        raise GuardError("not-found", f"Folder not found: {folder}")
    result = scan_tree(os.path.abspath(folder))
    result.update({"ok": True, "version": VERSION, "id": "", "url": os.path.abspath(folder), "dir": os.path.abspath(folder),
                   "head": "", "headSubject": "", "headDate": "", "scannedAt": int(time.time()), "verified": "", "diff": None})
    return result


def do_install(scan_id, commit="", assume_yes=False):
    if not re.match(r"^[a-z0-9._-]+$", scan_id or ""):
        raise GuardError("not-found", "Unknown scan id")
    base = os.path.join(work_root(), scan_id)
    try:
        with open(os.path.join(base, "scan.json"), encoding="utf-8") as handle:
            meta = json.load(handle)
    except (OSError, ValueError):
        raise GuardError("not-found", "That scan is gone from /tmp. Scan the URL again first.")
    repo = os.path.join(base, "repo")
    target = (commit or meta["head"]).lower()
    if target not in (meta["head"], meta.get("verified") or ""):
        raise GuardError("not-scanned", "Only the scanned HEAD or the verified commit of this scan can be installed")
    if git(["rev-parse", "HEAD"], cwd=repo)[1].strip() != meta["head"]:
        raise GuardError("tampered", "The scanned clone changed after the scan. Scan again.")

    stage = os.path.join(base, "install")
    shutil.rmtree(stage, ignore_errors=True)
    git(["clone", "--quiet", "--no-hardlinks", "--", repo, stage], budget_dir=stage)
    git(["checkout", "--quiet", "--detach", target], cwd=stage, budget_dir=stage)
    if git(["rev-parse", "HEAD"], cwd=stage)[1].strip() != target:
        raise GuardError("git-failed", "Could not check out the requested commit")
    manifest, problem = read_manifest(stage)
    if manifest is None:
        raise GuardError("not-a-plugin", problem)
    plugin_id = str(manifest.get("id", ""))
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", plugin_id) or ".." in plugin_id:
        raise GuardError("not-a-plugin", "The manifest has no valid plugin id")
    plugins = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config"), "omarchy", "plugins")
    if os.path.lexists(os.path.join(plugins, plugin_id)):
        raise GuardError("already-installed", f"{plugin_id} is already installed. Remove it first with: omarchy plugin remove {plugin_id}")

    if not assume_yes:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise GuardError("needs-confirmation", "Refusing to install without confirmation; pass --yes")
        print(f"Install {plugin_id} at commit {target[:12]} from {meta['url']}?")
        print(f"Last scan verdict: {meta.get('verdict', '?').upper()}. Plugins run unsandboxed inside omarchy-shell.")
        if input("Type 'yes' to install: ").strip().lower() != "yes":
            raise GuardError("cancelled", "Cancelled, nothing was installed")

    progress("installing")
    adder = shutil.which("omarchy-plugin-add")
    if not adder:
        raise GuardError("omarchy-missing", "omarchy-plugin-add was not found")
    done = subprocess.run([adder, stage, "--yes"], capture_output=True, stdin=subprocess.DEVNULL, timeout=GIT_TIMEOUT)
    if done.returncode != 0:
        lines = (done.stderr.decode("utf-8", "replace").strip() or done.stdout.decode("utf-8", "replace").strip()).splitlines()
        raise GuardError("install-failed", clean_text(lines[-1] if lines else "omarchy plugin add failed", 300))
    installed = os.path.join(plugins, plugin_id)
    # Point the checkout back at the real repository instead of /tmp.
    git(["remote", "set-url", "origin", meta["url"]], cwd=installed, check=False)
    shutil.rmtree(stage, ignore_errors=True)

    reviewed_path = os.path.join(state_dir(), "reviewed.json")
    try:
        with open(reviewed_path, encoding="utf-8") as handle:
            reviewed = json.load(handle)
    except (OSError, ValueError):
        reviewed = {}
    reviewed[plugin_id] = {"url": meta["url"], "commit": target, "verdict": meta.get("verdict", ""), "installedAt": int(time.time())}
    write_json_atomic(reviewed_path, reviewed)
    return {"ok": True, "pluginId": plugin_id, "commit": target, "path": installed,
            "next": f"omarchy plugin enable {plugin_id}"}


# ------------------------------------------------------------------- output

COLORS = {"danger": "31", "caution": "33", "safe": "32", HIGH: "31", MEDIUM: "33", INFO: "36"}


def paint(text, code, enabled):
    return f"\033[{code}m{text}\033[0m" if enabled else text


def print_report(result, color):
    verdict = result["verdict"]
    counts = result["counts"]
    print()
    print(paint(f"  {verdict.upper()}  ", "1;7;" + COLORS[verdict], color) + f"  risk {result['score']}/100")
    info = result.get("manifest") or {}
    if info:
        print(f"  {info.get('name') or '?'} {info.get('version') or ''}  ({info.get('id') or 'no id'})")
    if result.get("head"):
        print(f"  HEAD {result['head'][:12]}  {result['headSubject']}")
    print(f"  {counts[HIGH]} high · {counts[MEDIUM]} medium · {counts[INFO]} info · {result['files']} files")
    print(f"  {result['summary']}")
    last = None
    for finding in result["findings"]:
        if finding["severity"] != last:
            last = finding["severity"]
            print()
            print(paint(f"  {last.upper()} ({counts[last]})", "1;" + COLORS[last], color))
        where = finding["file"] + (f":{finding['line']}" if finding["line"] else "")
        flag = paint(" NEW", "1;35", color) if finding["new"] else ""
        print(f"    {paint(finding['rule'], COLORS[last], color)}  {where}{flag}")
        if finding["snippet"]:
            print(paint(f"        {finding['snippet']}", "2", color))
    if result["findingsTotal"] > len(result["findings"]):
        print(f"\n  … {result['findingsTotal'] - len(result['findings'])} more findings not shown")
    diff = result.get("diff")
    if diff:
        print()
        if not diff["ok"]:
            print(paint(f"  DIFF: {diff['error']}", "31", color))
        else:
            print(paint(f"  CHANGES SINCE VERIFIED COMMIT {diff['sha'][:12]}", "1", color))
            print(f"  {diff['summary']}")
            for entry in diff["files"]:
                print(f"    +{entry['added']:<5} -{entry['removed']:<5} {entry['path']}")
            print()
            for line in diff["lines"]:
                code = "32" if line.startswith("+") and not line.startswith("+++") else \
                    "31" if line.startswith("-") and not line.startswith("---") else \
                    "36" if line.startswith("@@") else "2"
                print("    " + paint(line, code, color))
            if diff["truncated"]:
                print(f"    … {diff['totalLines'] - len(diff['lines'])} more lines")
    if result.get("id"):
        print()
        print(f"  Scanned copy: {result['dir']}")
        print(f"  Install this exact commit:  plugin-guard install {result['id']}")
        if result.get("verified") and result["verified"] != result["head"]:
            print(f"  Install the verified commit: plugin-guard install {result['id']} --commit {result['verified'][:12]}")
    print()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="plugin-guard", description="Scan an Omarchy plugin before installing it.")
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("scan", help="clone a git URL into /tmp and scan it")
    p.add_argument("url")
    p.add_argument("--verified", default="", metavar="SHA", help="commit the marketplace verified; shows what changed since")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-save", action="store_true", help="do not update the bar widget's last result")
    p = sub.add_parser("scan-dir", help="scan a local folder without cloning")
    p.add_argument("folder")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("install", help="install a scanned commit with omarchy plugin add")
    p.add_argument("scan_id")
    p.add_argument("--commit", default="", metavar="SHA")
    p.add_argument("--yes", action="store_true", help="skip the interactive confirmation")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("last", help="show the last scan result")
    p.add_argument("--json", action="store_true")
    sub.add_parser("clean", help="delete scanned copies in /tmp and the last result")
    args = parser.parse_args(argv)
    as_json = getattr(args, "json", False)
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    last_path = os.path.join(state_dir(), "last.json")

    try:
        if args.command == "scan":
            try:
                result = do_scan(args.url, args.verified)
            except GuardError as error:
                if not args.no_save:
                    write_json_atomic(last_path, {"ok": False, "url": clean_text(args.url, 300), "scannedAt": int(time.time()),
                                                  "error": {"code": error.code, "message": error.message}})
                raise
            if not args.no_save:
                write_json_atomic(last_path, result)
        elif args.command == "scan-dir":
            result = do_scan_dir(args.folder)
        elif args.command == "install":
            commit = args.commit
            if commit and len(commit) < 40:
                base = os.path.join(work_root(), args.scan_id, "repo")
                if os.path.isdir(base):
                    code, out, _ = git(["rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}"], cwd=base, check=False)
                    commit = out.strip() if code == 0 else commit
            result = do_install(args.scan_id, commit, args.yes)
            try:  # let the panel show that this scan has been installed
                with open(last_path, encoding="utf-8") as handle:
                    last = json.load(handle)
                if last.get("id") == args.scan_id:
                    last["installed"] = {"pluginId": result["pluginId"], "commit": result["commit"], "at": int(time.time())}
                    write_json_atomic(last_path, last)
            except (OSError, ValueError):
                pass
            if as_json:
                print(json.dumps(result))
            else:
                print(f"Installed {result['pluginId']} at {result['commit'][:12]} into {result['path']}")
                print(f"Enable it with: {result['next']}")
            return 0
        elif args.command == "last":
            try:
                with open(last_path, encoding="utf-8") as handle:
                    result = json.load(handle)
            except (OSError, ValueError):
                raise GuardError("no-scan", "No plugin has been scanned yet")
            if not result.get("ok"):
                raise GuardError(result["error"]["code"], result["error"]["message"])
        else:
            root = work_root()
            for name in os.listdir(root):
                shutil.rmtree(os.path.join(root, name), ignore_errors=True)
            if os.path.exists(last_path):
                os.remove(last_path)
            print("Removed scanned copies and the last result")
            return 0
    except GuardError as error:
        if as_json:
            print(json.dumps({"ok": False, "error": {"code": error.code, "message": error.message}}))
        else:
            print(f"plugin-guard: {error.message}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130

    if as_json:
        print(json.dumps(result, ensure_ascii=False))
    else:
        print_report(result, color)
    return {"safe": 0, "caution": 0, "danger": 1}[result["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
