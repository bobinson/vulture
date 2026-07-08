# ruff: noqa
"""Deliberately vulnerable fixture for the OWASP-over-CWE pipeline test (feature 0063).

NOT production code. Each block plants a distinct CWE the CWE agent detects
deterministically (skills-only), chosen so the mapped OWASP categories span the
ENTIRE Top 10 for BOTH the 2021 and 2025 editions. Consumed by
tests/e2e/test_owasp_over_cwe_integration.py, which copies this directory into a
clean temp dir, runs the CWE skills to produce real findings, and asserts the
OWASP mapper categorizes them into all 10 categories per edition.

Lives under tests/fixtures/ (a scanner SKIP_DIR) so the repo's own audits never
flag it; the test scans a temp copy, not this path.

Planted CWE -> OWASP category (2021 / 2025):
  CWE-89  SQL injection            -> A03 / A05   (Injection)
  CWE-78  OS command injection     -> A03 / A05   (Injection)
  CWE-328 weak hash (md5)          -> A02 / A04   (Cryptographic Failures)
  CWE-798 hardcoded secret         -> A07 / A07   (Auth/Identification Failures)
  CWE-918 SSRF                     -> A10 / A01   (SSRF folds into Access Control in 2025)
  CWE-502 unsafe deserialization   -> A08 / A08   (Software & Data Integrity)
  CWE-611 XXE                      -> A05 / A02   (Security Misconfiguration)
  CWE-532 sensitive data in logs   -> A09 / A09   (Logging & Monitoring/Alerting)
  CWE-755/248 swallowed exception  -> (—) / A10   (Mishandling of Exceptional Conditions)
  CWE-312 cleartext of secret      -> A04 / A06   (Insecure Design)
  route handlers w/o authz         -> A01 / A01   (Broken Access Control: CWE-862/639/352)
  requirements.txt vulnerable pin  -> A06 / A03   (Vulnerable Components / Software Supply Chain: CWE-937/1104)
"""
import hashlib
import logging
import os
import pickle
import xml.etree.ElementTree as etree

import requests
from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)
API_KEY = "sk-live-abcdef0123456789abcdef01"  # CWE-798 hardcoded secret -> A07


@app.route("/user")
def get_user():
    uid = request.args["id"]
    query = f"SELECT * FROM users WHERE id = {uid}"  # CWE-89 SQLi -> A03 (2021) / A05 (2025)
    return db.execute(query)


@app.route("/run", methods=["POST"])
def run_cmd():
    os.system(request.form["cmd"])  # CWE-78 command injection -> A03 (2021) / A05 (2025)
    return "ok"


def hash_pw(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # CWE-328 weak hash -> A02 (2021) / A04 (2025)


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"]).text  # CWE-918 SSRF -> A10 (2021) / A01 (2025)


@app.route("/load", methods=["POST"])
def load_blob():
    return str(pickle.loads(request.data))  # CWE-502 unsafe deserialization -> A08


@app.route("/config", methods=["POST"])
def parse_config():
    return str(etree.parse(request.args["path"]))  # CWE-611 XXE -> A05 (2021) / A02 (2025)


@app.route("/login", methods=["POST"])
def login():
    pw = request.form["password"]
    logging.warning(f"auth failure token={API_KEY} pw={pw}")  # CWE-532 sensitive data in logs -> A09
    try:
        return authenticate(pw)
    except Exception:  # CWE-755/248 swallowed exception -> A10 (2025)
        pass
    return "no"
