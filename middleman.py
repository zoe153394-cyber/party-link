from flask import Flask, redirect, abort, request
from datetime import datetime, timezone
import hmac
import hashlib
import time

app = Flask(__name__)

SECRET_KEY = "WE-NEED-TO-PARTY"
SIGNING_URL = "https://party-link.onrender.com/go"  # Used for signature verification
TARGET_URL = "https://metabook.gr/margant"           # Where to redirect after validation

def validate_link(expires: int, sig: str) -> tuple[bool, str]:
    url_to_verify = f"{SIGNING_URL}?expires={expires}"
    expected_sig = hmac.new(
        SECRET_KEY.encode(),
        url_to_verify.encode(),
        hashlib.sha256
    ).hexdigest()
    if time.time() > expires:
        return False, "Link has expired"
    if not hmac.compare_digest(expected_sig, sig):
        return False, "Invalid signature"
    return True, "Valid"

@app.route("/go")
def go():
    expires = request.args.get("expires")
    sig = request.args.get("sig")
    if not expires or not sig:
        abort(403)
    is_valid, reason = validate_link(int(expires), sig)
    if not is_valid:
        abort(403, description=reason)
    return redirect(TARGET_URL)

if __name__ == "__main__":
    app.run(debug=True)
