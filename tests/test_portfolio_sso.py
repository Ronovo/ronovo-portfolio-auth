import time

import jwt
import pytest
from flask import Flask, jsonify, redirect

from ronovo_portfolio_auth import portfolio_sso

KEY, PUBLIC_KEY = portfolio_sso.new_key_pair()
APP_ID = "test-app"


@pytest.fixture(autouse=True)
def sso_env(monkeypatch):
    monkeypatch.setenv("PORTFOLIO_SSO_URL", "https://portfolio.example/")
    monkeypatch.setenv("PORTFOLIO_SSO_PUBLIC_KEY", PUBLIC_KEY)


def make_app(on_error=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", TESTING=True)
    app.logins = []

    def on_login(account, next_path):
        app.logins.append((account, next_path))
        return redirect(next_path or "/home")

    portfolio_sso.add_flask_routes(app, APP_ID, on_login, on_error)
    return app


def token(app_id=APP_ID, **claims):
    return portfolio_sso.issue(KEY, app_id, 7, "player", **claims)


def unsigned_claims(**claims):
    return {"iss": "portfolio", "aud": APP_ID, "sub": "7", "exp": int(time.time()) + 60, **claims}


def start_login(client, **query):
    response = client.get("/sso/login", query_string=query)
    with client.session_transaction() as session:
        return response, session.get("portfolio_state")


def test_enabled_needs_both_settings(monkeypatch):
    assert portfolio_sso.enabled()
    monkeypatch.setenv("PORTFOLIO_SSO_PUBLIC_KEY", " ")
    assert not portfolio_sso.enabled()


def test_portfolio_url_drops_the_trailing_slash():
    assert portfolio_sso.portfolio_url() == "https://portfolio.example"


def test_key_pair_round_trips_through_env_text():
    loaded = portfolio_sso.load_private_key(portfolio_sso.private_key_text(KEY))
    assert portfolio_sso.verify(portfolio_sso.issue(loaded, APP_ID, 1, "a"), APP_ID) == {"sub": "1", "username": "a"}


def test_issue_signs_the_expected_claims():
    claims = jwt.decode(token(), KEY.public_key(), algorithms=["RS256"], audience=APP_ID, issuer="portfolio")
    assert claims["sub"] == "7"
    assert claims["name"] == "player"
    assert claims["exp"] - claims["iat"] == portfolio_sso.TOKEN_SECONDS


def test_two_tokens_for_one_login_are_never_the_same():
    assert token() != token()


@pytest.mark.parametrize("bad", [
    "",
    "not.a.token",
    token(app_id="other-app"),
    token(seconds=-1),
    jwt.encode(unsigned_claims(iss="someone"), KEY, algorithm="RS256"),
    jwt.encode({k: v for k, v in unsigned_claims().items() if k != "sub"}, KEY, algorithm="RS256"),
    jwt.encode(unsigned_claims(), "shared secret long enough for sha256 hmac", algorithm="HS256"),
])
def test_verify_refuses_bad_tokens(bad):
    assert portfolio_sso.verify(bad, APP_ID) is None


def test_verify_is_off_without_the_settings(monkeypatch):
    monkeypatch.delenv("PORTFOLIO_SSO_URL")
    assert portfolio_sso.verify(token(), APP_ID) is None


def test_verify_tolerates_a_missing_name():
    unnamed = jwt.encode(unsigned_claims(), KEY, algorithm="RS256")
    assert portfolio_sso.verify(unnamed, APP_ID) == {"sub": "7", "username": ""}


@pytest.mark.parametrize("target, expected", [
    ("/play", "/play"),
    ("/play?table=1#x", "/play?table=1#x"),
    ("", None),
    (None, None),
    ("play", None),
    ("//evil.example/x", None),
    ("https://evil.example/x", None),
    ("/back\\slash", None),
    ("/line\nbreak", None),
])
def test_safe_next_keeps_only_paths_on_this_site(target, expected):
    assert portfolio_sso.safe_next(target) == expected


def test_login_sends_the_browser_to_the_portfolio():
    client = make_app().test_client()
    response, state = start_login(client)
    assert response.status_code == 302
    assert response.headers["Location"] == portfolio_sso.authorize_url(
        APP_ID, "http://localhost/sso/callback", state)


def test_login_is_off_without_the_settings(monkeypatch):
    monkeypatch.delenv("PORTFOLIO_SSO_URL")
    assert make_app().test_client().get("/sso/login").status_code == 404


def test_callback_logs_the_account_in():
    app = make_app()
    client = app.test_client()
    _, state = start_login(client)
    response = client.post("/sso/callback", data={"state": state, "token": token()})
    assert response.headers["Location"] == "/home"
    assert app.logins == [({"sub": "7", "username": "player"}, None)]


def test_callback_keeps_the_next_path():
    app = make_app()
    client = app.test_client()
    _, state = start_login(client, next="/table/3")
    response = client.post("/sso/callback", data={"state": state, "token": token()})
    assert response.headers["Location"] == "/table/3"
    assert app.logins[0][1] == "/table/3"


def test_login_forgets_a_next_path_it_cannot_use():
    app = make_app()
    client = app.test_client()
    start_login(client, next="/table/3")
    _, state = start_login(client, next="https://evil.example/")
    client.post("/sso/callback", data={"state": state, "token": token()})
    assert app.logins[0][1] is None


@pytest.mark.parametrize("data", [
    {"state": "wrong", "token": token()},
    {"token": token()},
])
def test_callback_refuses_a_wrong_state(data):
    client = make_app().test_client()
    start_login(client)
    assert client.post("/sso/callback", data=data).status_code == 400


def test_callback_refuses_without_a_login_in_progress():
    app = make_app()
    assert app.test_client().post("/sso/callback", data={"state": "s", "token": token()}).status_code == 400
    assert app.logins == []


def test_callback_refuses_a_second_submit():
    app = make_app()
    client = app.test_client()
    _, state = start_login(client)
    data = {"state": state, "token": token()}
    client.post("/sso/callback", data=data)
    assert client.post("/sso/callback", data=data).status_code == 400
    assert len(app.logins) == 1


def test_callback_refuses_a_bad_token():
    client = make_app().test_client()
    _, state = start_login(client)
    assert client.post("/sso/callback", data={"state": state, "token": token(app_id="other")}).status_code == 400


def test_every_refusal_has_a_message():
    assert set(portfolio_sso.LOGIN_MESSAGES) == {portfolio_sso.LOGIN_EXPIRED, portfolio_sso.LOGIN_INVALID}


def test_on_error_answers_refused_callbacks():
    app = make_app(on_error=lambda reason: (jsonify(reason=reason), 409))
    client = app.test_client()
    assert client.post("/sso/callback", data={"state": "s", "token": token()}).get_json() == {"reason": "expired"}
    _, state = start_login(client)
    response = client.post("/sso/callback", data={"state": state, "token": "junk"})
    assert response.status_code == 409
    assert response.get_json() == {"reason": "invalid"}
    assert app.logins == []
