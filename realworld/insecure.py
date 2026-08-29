# Deliberately insecure "real-world" Python -- the security mistakes that ship in
# real services. Sample input for the detector; do not run or import.
import hashlib
import pickle
import subprocess
import tempfile

import requests
import yaml


def store_password(pw):
    # weak-hash: MD5 for a password. Broken.
    return hashlib.md5(pw.encode()).hexdigest()


def fetch(url):
    # tls-verify-disabled + py-requests-no-timeout on the same call.
    return requests.get(url, verify=False)


def scratch_file():
    # py-tempfile-insecure: mktemp is a TOCTOU race.
    return tempfile.mktemp()


def load_config(text):
    # py-yaml-load: default loader can build arbitrary objects.
    return yaml.load(text)


def restore(blob):
    # py-insecure-deserialize: unpickling untrusted data == code execution.
    return pickle.loads(blob)


def run(cmd):
    # py-subprocess-shell: shell=True => command injection.
    return subprocess.run(cmd, shell=True)


def calculate(expr):
    # dangerous-eval: eval on input is remote code execution.
    return eval(expr)


# debug-enabled: interactive debugger reachable in production (Flask => RCE).
DEBUG = True
