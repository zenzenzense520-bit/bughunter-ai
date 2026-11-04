"""Intentionally vulnerable sample for BugHunter SAST tests.

Each function contains exactly one bug that the bundled custom Semgrep rules
must detect. This file is TEST DATA: never import or run it.
"""

import hashlib
import pickle
import subprocess

import requests
import yaml


def evaluate(expr):
    return eval(expr)


def run_command(name):
    return subprocess.run("ping " + name, shell=True, capture_output=True)


def find_user(cursor, name):
    return cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


def load_session(blob):
    return pickle.loads(blob)


def load_config(data):
    return yaml.load(data)


def fetch(url):
    return requests.get(url, verify=False, timeout=5)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


API_KEY = "sk-live-1234567890abcdef"
DB_PASSWORD = "hunter2"
