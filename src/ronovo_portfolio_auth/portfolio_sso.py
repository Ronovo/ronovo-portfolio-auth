"""Log in with a portfolio account.

The app sends the player to the portfolio's /sso/authorize, which posts a short-lived token signed with the
portfolio's private key back to the app's /sso/callback. The app checks it with PORTFOLIO_SSO_PUBLIC_KEY.
Without PORTFOLIO_SSO_URL and PORTFOLIO_SSO_PUBLIC_KEY set, portfolio login is off and the app runs on its own.
Both sides of the token, issue() for the portfolio and verify() for the apps, live here.
"""
import base64
import os
import secrets
import time
from functools import lru_cache
from typing import Optional
from urllib.parse import urlencode, urlsplit

ISSUER = "portfolio"
TOKEN_SECONDS = 300
CALLBACK_PATH = "sso/callback"
APP_PARAM = "app"
RETURN_PARAM = "return"
STATE_PARAM = "state"
NEXT_PARAM = "next"

# Why a callback was refused: the state did not match (back button, double submit, expired session) or the
# token did not check out.
LOGIN_EXPIRED = "expired"
LOGIN_INVALID = "invalid"
LOGIN_MESSAGES = {
    LOGIN_EXPIRED: "Your portfolio login expired. Try again.",
    LOGIN_INVALID: "That portfolio login didn't check out. Try again.",
}


@lru_cache
def _public_key(raw: str):
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    return load_der_public_key(base64.b64decode(raw))


def enabled() -> bool:
    return bool(os.environ.get("PORTFOLIO_SSO_URL", "").strip()
                and os.environ.get("PORTFOLIO_SSO_PUBLIC_KEY", "").strip())


def portfolio_url() -> str:
    """The portfolio's address. Its /sso/me tells a page which portfolio account the browser is logged in to."""
    return os.environ["PORTFOLIO_SSO_URL"].strip().rstrip("/")


def new_state() -> str:
    return secrets.token_urlsafe(16)


def safe_next(target) -> Optional[str]:
    """target when it is a path on this site, so a link can't bounce a login elsewhere; otherwise None"""
    target = target or ""
    parts = urlsplit(target)
    on_site = (target.startswith("/") and target.isprintable() and "\\" not in target
               and not parts.scheme and not parts.netloc)
    return target if on_site else None


def authorize_url(app_id: str, callback_url: str, state: str) -> str:
    query = urlencode({APP_PARAM: app_id, RETURN_PARAM: callback_url, STATE_PARAM: state})
    return f"{portfolio_url()}/sso/authorize?{query}"


def new_key_pair():
    """A new signing key, and its public half as PORTFOLIO_SSO_PUBLIC_KEY holds it (base64 DER)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, base64.b64encode(public).decode()


def private_key_text(key) -> str:
    """A signing key as PORTFOLIO_SSO_PRIVATE_KEY holds it (base64 DER)."""
    from cryptography.hazmat.primitives import serialization
    return base64.b64encode(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption())).decode()


def load_private_key(text: str):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_der_private_key(base64.b64decode(text), password=None)


def issue(key, app_id: str, user_id, username: str, seconds: int = TOKEN_SECONDS) -> str:
    """A login token for one app, signed by the portfolio."""
    import jwt
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": app_id, "sub": str(user_id), "name": username, "iat": now, "exp": now + seconds,
              "jti": secrets.token_urlsafe(8)}
    return jwt.encode(claims, key, algorithm="RS256")


def verify(token: str, app_id: str) -> Optional[dict]:
    """The portfolio account ({"sub", "username"}) a token was issued to for this app, or None"""
    if not enabled() or not token:
        return None
    import jwt
    try:
        claims = jwt.decode(token, _public_key(os.environ["PORTFOLIO_SSO_PUBLIC_KEY"].strip()), algorithms=["RS256"],
                            audience=app_id, issuer=ISSUER, options={"require": ["exp", "iss", "aud", "sub"]})
    except (jwt.InvalidTokenError, ValueError):
        return None
    return {"sub": claims["sub"], "username": claims.get("name", "")}


def add_flask_routes(app, app_id: str, on_login, on_error=None):
    """Adds /sso/login and /sso/callback to a Flask app.

    on_login(account, next_path) runs once a token checks out and returns the response. next_path is the
    same-site path /sso/login was given as ?next=, or None. on_error(reason) returns the response for a refused
    callback, with reason LOGIN_EXPIRED or LOGIN_INVALID; without it the callback answers 400."""
    from flask import abort, redirect, request, session, url_for

    def refuse(reason):
        return on_error(reason) if on_error else abort(400)

    @app.get("/sso/login")
    def sso_login():
        if not enabled():
            abort(404)
        session["portfolio_state"] = state = new_state()
        session.pop("portfolio_next", None)
        next_path = safe_next(request.args.get(NEXT_PARAM))
        if next_path:
            session["portfolio_next"] = next_path
        return redirect(authorize_url(app_id, url_for("sso_callback", _external=True), state))

    @app.post("/" + CALLBACK_PATH)
    def sso_callback():
        state = session.pop("portfolio_state", None)
        next_path = session.pop("portfolio_next", None)
        if state is None or not secrets.compare_digest(state.encode(), request.form.get(STATE_PARAM, "").encode()):
            return refuse(LOGIN_EXPIRED)
        account = verify(request.form.get("token", ""), app_id)
        if account is None:
            return refuse(LOGIN_INVALID)
        return on_login(account, next_path)
