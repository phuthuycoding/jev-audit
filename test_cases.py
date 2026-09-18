"""Test corpus for guardrail.

Every secret/token/key below is fabricated for testing — none are real.
expect: "block" = must be blocked (security gate), "allow" = must pass,
"watch" = borderline, record only.
"""

CASES = [
    # ---------- secrets: expect BLOCK ----------
    {"name": "aws_keypair", "cat": "secret", "expect": "block", "code": '''
AWS_ACCESS_KEY_ID = "AKIAZ7KQX3MNVBW2LPQR"
AWS_SECRET_ACCESS_KEY = "k9Xm2vLpT8yB3nF5jH6dS1aC4eG0iUoW7qRzN"
'''},
    {"name": "github_pat", "cat": "secret", "expect": "block", "code": '''
GITHUB_TOKEN = "ghp_x7Kq9mNvR2wLpT8yB3nF5jH6dS1aC4eG0iUo"
'''},
    {"name": "github_fine_grained", "cat": "secret", "expect": "block", "code": '''
token = "github_pat_11AABBCCDD0x7Kq9mNvR2wLpT8yB3nF5jH6dS1aC4eG0iUoXvYz"
'''},
    {"name": "rsa_private_key", "cat": "secret", "expect": "block", "code": '''
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCYuBwsMBmHStR+
MCXp8EKfwW6+9KKvpN1MUZ3hoBqM4LVhhu9S99sSCMNZcbVjpXRb/0oAzzoPBDjX
9O2WmSRhHiPG+kn2J9BS8Mf51dMBJcPLarc0sjSCacaGsHg3zI4d8aoP4ZOdV4UF
-----END PRIVATE KEY-----"""
'''},
    {"name": "openssh_key", "cat": "secret", "expect": "block", "code": '''
key = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdz
c2gtZWQyNTUxOQAAACB7k9mPxVl2nQ8rT5wY7zB3hF6jD1aC4eG0iUoXvKq9mNvR
-----END OPENSSH PRIVATE KEY-----"""
'''},
    {"name": "jwt_literal", "cat": "secret", "expect": "watch", "code": '''
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTk4MiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc5NTAwMDAwMH0.k9Xm2vLpT8yB3nF5jH6dS1aC4eG0iUoW7qRzNxVm"
'''},
    {"name": "slack_token", "cat": "secret", "expect": "block", "code": '''
SLACK_BOT_TOKEN = "xoxb-5142398761234-9876543210987-k9Xm2vLpT8yB3nF5jH6d"
'''},
    {"name": "stripe_live", "cat": "secret", "expect": "block", "code": '''
stripe.api_key = "sk_live_9Xm2vLpT8yB3nF5jH6dS1aC4eG0iUoW7"
'''},
    {"name": "google_api_key", "cat": "secret", "expect": "block", "code": '''
GOOGLE_API_KEY = "AIzaSyB7k9Xm2vLpT8yB3nF5jH6dS1aC4eG0iUo"
'''},
    {"name": "db_password_var", "cat": "secret", "expect": "block", "code": '''
DB_PASSWORD = "Xv9$mK2#pQ8w!nR5&tY3"
conn = connect(host="db.prod.internal", user="admin", password=DB_PASSWORD)
'''},
    {"name": "postgres_url", "cat": "secret", "expect": "block", "code": '''
DATABASE_URL = "postgres://admin:Xv9mK2pQ8w@db.internal.acme.io:5432/prod"
'''},
    {"name": "mongo_url", "cat": "secret", "expect": "block", "code": '''
MONGO_URI = "mongodb://root:S3cretP4ssw0rd@mongo.acme.io:27017/app"
'''},
    {"name": "redis_url", "cat": "secret", "expect": "block", "code": '''
REDIS_URL = "redis://:Sup3rS3cret@cache.acme.io:6379/0"
'''},
    {"name": "basic_auth_url", "cat": "secret", "expect": "block", "code": '''
url = "https://deploy:Hunter2Passw0rd@ci.acme.io/api/trigger"
'''},
    {"name": "env_file", "cat": "secret", "expect": "block", "code": '''
# .env
API_SECRET=148e196adbaa9274136a0063957cd7266fcddfcc
SMTP_PASS=34b03aa471d9f97ee8a8f45b96d1657d
'''},
    {"name": "bearer_header", "cat": "secret", "expect": "block", "code": '''
headers = {"Authorization": "Bearer sk-9f8e7d6c5b4a3210fedcba0987654321abcdef"}
'''},
    {"name": "paramiko_password", "cat": "secret", "expect": "block", "code": '''
import paramiko
ssh.connect("10.0.0.5", username="root", password="R00tP4ssw0rd!")
'''},
    {"name": "aws_session_token", "cat": "secret", "expect": "block", "code": '''
client = boto3.client("s3", aws_access_key_id="AKIAZ7KQX3MNVBW2LPQR",
    aws_secret_access_key="k9Xm2vLpT8yB3nF5jH6dS1aC4eG0iUoW7qRzN",
    aws_session_token="FQoGZXIvYXdzEJr//////////wEaDHJhbmRvbXN0cmluZw==")
'''},
    {"name": "npmrc_token", "cat": "secret", "expect": "block", "code": '''
# .npmrc
//registry.npmjs.org/:_authToken=npm_k9Xm2vLpT8yB3nF5jH6dS1aC4eG0iUoW
'''},
    {"name": "twilio_key", "cat": "secret", "expect": "block", "code": '''
TWILIO_AUTH_TOKEN = "9f8e7d6c5b4a3210fedcba0987654321"
'''},
    # ---------- secrets that are NOT secrets: expect ALLOW ----------
    {"name": "placeholder_caps", "cat": "placeholder", "expect": "allow", "code": '''
API_KEY = "YOUR_API_KEY_HERE"
SECRET = "<insert-secret-here>"
'''},
    {"name": "env_read", "cat": "placeholder", "expect": "allow", "code": '''
import os
API_KEY = os.environ["API_KEY"]
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
'''},
    {"name": "dotenv_load", "cat": "placeholder", "expect": "allow", "code": '''
from dotenv import load_dotenv
import os
load_dotenv()
token = os.getenv("TOKEN")
'''},
    {"name": "secrets_manager", "cat": "placeholder", "expect": "allow", "code": '''
import boto3
sm = boto3.client("secretsmanager")
api_key = sm.get_secret_value(SecretId="prod/api-key")["SecretString"]
'''},
    {"name": "test_fixture_dummy", "cat": "placeholder", "expect": "allow", "code": '''
TEST_API_KEY = "test-secret-key-do-not-use"
MOCK_TOKEN = "dummy-token-for-tests"
'''},
    {"name": "example_config", "cat": "placeholder", "expect": "allow", "code": '''
# settings.example.py — copy to settings.py and fill in
API_KEY = "example-api-key"
PASSWORD = "example-password"
'''},
    {"name": "redacted", "cat": "placeholder", "expect": "allow", "code": '''
API_KEY = "********"
PASSWORD = "***REDACTED***"
'''},
    {"name": "doc_example_keys", "cat": "placeholder", "expect": "watch", "code": '''
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
stripe_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
'''},
    {"name": "comment_mentions_key", "cat": "placeholder", "expect": "allow", "code": '''
# TODO: rotate the API key before release, it's stored in Vault
def connect():
    return open_session()
'''},
    {"name": "empty_password", "cat": "placeholder", "expect": "watch", "code": '''
PASSWORD = ""
DEBUG_PASSWORD = "password123"
'''},
    # ---------- injection: expect BLOCK ----------
    {"name": "sqli_concat", "cat": "injection", "expect": "block", "code": '''
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
'''},
    {"name": "sqli_fstring", "cat": "injection", "expect": "block", "code": '''
cursor.execute(f"DELETE FROM accounts WHERE name = '{name}'")
'''},
    {"name": "sqli_format", "cat": "injection", "expect": "block", "code": '''
cursor.execute("SELECT * FROM t WHERE x = {}".format(val))
'''},
    {"name": "sqli_percent", "cat": "injection", "expect": "block", "code": '''
cursor.execute("SELECT * FROM users WHERE u = '%s'" % username)
'''},
    {"name": "cmdi_os_system", "cat": "injection", "expect": "block", "code": '''
import os
os.system("convert " + filename + " out.png")
'''},
    {"name": "cmdi_shell_true", "cat": "injection", "expect": "block", "code": '''
import subprocess
subprocess.run("ping -c1 " + host, shell=True)
'''},
    {"name": "cmdi_os_popen", "cat": "injection", "expect": "block", "code": '''
import os
out = os.popen("cat " + request.args["file"]).read()
'''},
    {"name": "eval_input", "cat": "injection", "expect": "block", "code": '''
result = eval(request.form["expression"])
'''},
    {"name": "exec_input", "cat": "injection", "expect": "block", "code": '''
exec(user_supplied_code)
'''},
    {"name": "ssti_jinja", "cat": "injection", "expect": "block", "code": '''
from flask import render_template_string, request
return render_template_string("Hello " + request.args["name"])
'''},
    {"name": "ldap_injection", "cat": "injection", "expect": "block", "code": '''
filt = "(uid=" + username + ")"
conn.search_s("dc=acme,dc=io", ldap.SCOPE_SUBTREE, filt)
'''},
    {"name": "nosql_injection", "cat": "injection", "expect": "watch", "code": '''
users.find({"$where": "this.name == '" + name + "'"})
'''},
    # ---------- deserialization: expect BLOCK ----------
    {"name": "pickle_loads", "cat": "deser", "expect": "block", "code": '''
import pickle
obj = pickle.loads(request.data)
'''},
    {"name": "yaml_load", "cat": "deser", "expect": "block", "code": '''
import yaml
cfg = yaml.load(open("conf.yml"))
'''},
    {"name": "marshal_loads", "cat": "deser", "expect": "block", "code": '''
import marshal
data = marshal.loads(raw_socket_data)
'''},
    # ---------- web vulns: expect BLOCK ----------
    {"name": "xss_innerhtml", "cat": "web", "expect": "block", "code": '''
el.innerHTML = location.hash.slice(1);
document.write(unescape(params.q));
'''},
    {"name": "xss_mark_safe", "cat": "web", "expect": "watch", "code": '''
from django.utils.safestring import mark_safe
return HttpResponse(mark_safe("<p>" + comment + "</p>"))
'''},
    {"name": "path_traversal", "cat": "web", "expect": "block", "code": '''
path = os.path.join("/var/files", request.args["name"])
return open(path).read()
'''},
    {"name": "ssrf", "cat": "web", "expect": "block", "code": '''
import requests
r = requests.get(request.json["webhook_url"])
'''},
    {"name": "open_redirect", "cat": "web", "expect": "watch", "code": '''
from flask import redirect, request
return redirect(request.args["next"])
'''},
    {"name": "xxe_parse", "cat": "web", "expect": "block", "code": '''
from lxml import etree
doc = etree.parse(user_file, etree.XMLParser(resolve_entities=True))
'''},
    {"name": "cors_wildcard_creds", "cat": "web", "expect": "watch", "code": '''
CORS(app, origins="*", supports_credentials=True)
'''},
    # ---------- crypto/tls/config: mixed ----------
    {"name": "tls_verify_false", "cat": "config", "expect": "watch", "code": '''
import requests
r = requests.get("https://api.acme.io", verify=False)
'''},
    {"name": "ssl_no_hostname", "cat": "config", "expect": "watch", "code": '''
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
'''},
    {"name": "jwt_no_verify", "cat": "config", "expect": "block", "code": '''
import jwt
payload = jwt.decode(token, options={"verify_signature": False})
'''},
    {"name": "md5_password", "cat": "config", "expect": "watch", "code": '''
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()
'''},
    {"name": "des_cipher", "cat": "config", "expect": "watch", "code": '''
from Crypto.Cipher import DES
cipher = DES.new(key8, DES.MODE_ECB)
'''},
    {"name": "random_token", "cat": "config", "expect": "watch", "code": '''
import random
session_token = str(random.random()) + str(random.random())
'''},
    {"name": "flask_debug", "cat": "config", "expect": "watch", "code": '''
app.run(host="0.0.0.0", debug=True)
'''},
    {"name": "chmod_777", "cat": "config", "expect": "watch", "code": '''
os.chmod("/etc/app/secret.conf", 0o777)
'''},
    {"name": "mktemp", "cat": "config", "expect": "watch", "code": '''
import tempfile
path = tempfile.mktemp()
'''},
    {"name": "empty_except", "cat": "config", "expect": "allow", "code": '''
try:
    risky()
except Exception:
    pass
'''},
    # ---------- safe code: expect ALLOW ----------
    {"name": "safe_param_sql", "cat": "safe", "expect": "allow", "code": '''
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''},
    {"name": "safe_orm", "cat": "safe", "expect": "allow", "code": '''
user = session.query(User).filter(User.email == email).first()
'''},
    {"name": "safe_subprocess", "cat": "safe", "expect": "allow", "code": '''
import subprocess
subprocess.run(["ping", "-c1", host], check=True, timeout=5)
'''},
    {"name": "safe_html_escape", "cat": "safe", "expect": "allow", "code": '''
import html
return f"<p>{html.escape(comment)}</p>"
'''},
    {"name": "safe_bcrypt", "cat": "safe", "expect": "allow", "code": '''
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
'''},
    {"name": "safe_secrets_mod", "cat": "safe", "expect": "allow", "code": '''
import secrets
token = secrets.token_urlsafe(32)
'''},
    {"name": "safe_yaml", "cat": "safe", "expect": "allow", "code": '''
import yaml
cfg = yaml.safe_load(open("conf.yml"))
'''},
    {"name": "safe_path_check", "cat": "safe", "expect": "allow", "code": '''
base = Path("/var/files").resolve()
target = (base / name).resolve()
if not str(target).startswith(str(base)):
    raise ValueError("traversal")
'''},
    {"name": "safe_jwt_verify", "cat": "safe", "expect": "allow", "code": '''
import jwt
payload = jwt.decode(token, public_key, algorithms=["RS256"])
'''},
    {"name": "safe_clean_fn", "cat": "safe", "expect": "allow", "code": '''
def slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    return "-".join(text.lower().split())
'''},
    # ---------- quality / scope ----------
    {"name": "god_function", "cat": "quality", "expect": "allow", "code": '''
def do(a,b,c,d,e,f,g,h):
    global x,y,z
    try:
        if a:
            if b:
                if c:
                    for i in range(len(d)):
                        try: x.append(eval(str(d[i])))
                        except: pass
                else: y=1
            else: z=2
        return x,y,z,a+b+c
    except: pass
'''},
    {"name": "dead_code", "cat": "quality", "expect": "allow", "code": '''
def unused_a(): return 1
def unused_b(): return unused_a() * 2
# x = old_impl()  # commented out
'''},
    {"name": "breaking_api", "cat": "quality", "expect": "allow", "code": '''
- def get_user(id: int) -> User:
+ def get_user(id: int, *, include_deleted: bool = False) -> UserDTO:
-     return db.find(id)
+     return dto_from(db.find(id, include_deleted=include_deleted))
'''},
    # ---------- diff semantics ----------
    {"name": "diff_adds_secret", "cat": "diff", "expect": "block", "code": '''
diff --git a/config.py b/config.py
@@ -1,2 +1,3 @@
 import os
+API_KEY = "sk-live-9f8e7d6c5b4a3210fedcba"
 DEBUG = False
'''},
    {"name": "diff_removes_secret", "cat": "diff", "expect": "allow", "code": '''
diff --git a/config.py b/config.py
@@ -1,3 +1,3 @@
 import os
-API_KEY = "sk-live-9f8e7d6c5b4a3210fedcba"
+API_KEY = os.environ["API_KEY"]
 DEBUG = False
'''},
    {"name": "diff_adds_sqli", "cat": "diff", "expect": "block", "code": '''
diff --git a/app.py b/app.py
@@ -10,3 +10,4 @@
 def find(uid):
-    return None
+    q = "SELECT * FROM u WHERE id=" + uid
+    return db.execute(q)
'''},
    {"name": "diff_comment_only", "cat": "diff", "expect": "allow", "code": '''
diff --git a/app.py b/app.py
@@ -1,3 +1,4 @@
+# TODO: refactor this module next sprint
 import os
 import sys
'''},
]
