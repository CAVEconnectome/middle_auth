import json
import os
from urllib.parse import unquote

from mitmproxy import http

DEFAULT_EMAIL = "mock.user@example.com"
DEFAULT_NAME = "Mock User"
CODE_EMAILS = {}
TOKEN_EMAILS = {}
SHARED_EMAIL_FILE = os.environ.get("OAUTH_TEST_EMAIL_FILE", "/oauth-shared/test_email.txt")


def _email_from_shared_file():
    try:
        with open(SHARED_EMAIL_FILE, "r", encoding="utf-8") as file:
            email = file.read().strip()
            return email or None
    except FileNotFoundError:
        return None


def _email_for_code(code):
    if code in CODE_EMAILS:
        return CODE_EMAILS[code]
    if code and code.startswith("mock-code-email-"):
        return unquote(code[len("mock-code-email-") :])
    return DEFAULT_EMAIL


def _json_response(status_code, payload):
    return http.Response.make(
        status_code,
        json.dumps(payload),
        {"Content-Type": "application/json"},
    )


def _extract_bearer_token(flow: http.HTTPFlow):
    auth_header = flow.request.headers.get("authorization")
    if not auth_header:
        return None
    parts = auth_header.split(" ", 1)
    if len(parts) != 2:
        return None
    return parts[1].strip()


def _email_for_token(token):
    if token and token in TOKEN_EMAILS:
        return TOKEN_EMAILS[token]
    return DEFAULT_EMAIL


def request(flow: http.HTTPFlow) -> None:
    url = flow.request.pretty_url

    if url.startswith("https://accounts.google.com/o/oauth2/auth"):
        redirect_uri = flow.request.query.get("redirect_uri")
        state = flow.request.query.get("state")
        email = flow.request.query.get("x_test_email") or _email_from_shared_file() or DEFAULT_EMAIL
        if not redirect_uri:
            flow.response = http.Response.make(400, b"missing redirect_uri")
            return
        code = f"mock-code-{len(CODE_EMAILS) + 1}"
        CODE_EMAILS[code] = email
        location = f"{redirect_uri}?code={code}"
        if state:
            location += f"&state={state}"

        flow.response = http.Response.make(302, b"", {"Location": location})
        return

    if url.startswith("https://accounts.google.com/o/oauth2/token") or url.startswith(
        "https://oauth2.googleapis.com/token"
    ):
        code = flow.request.urlencoded_form.get("code")
        email = _email_for_code(code)
        access_token = f"mock-access-token-{code or 'default'}"
        TOKEN_EMAILS[access_token] = email
        flow.response = _json_response(
            200,
            {
                "access_token": access_token,
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock-refresh-token",
            },
        )
        return

    if url.startswith("https://www.googleapis.com/oauth2/v2/userinfo"):
        token = _extract_bearer_token(flow)
        email = _email_for_token(token)
        flow.response = _json_response(
            200,
            {"email": email, "name": DEFAULT_NAME},
        )
        return

    if url.startswith("https://www.googleapis.com/userinfo/v2/me"):
        token = _extract_bearer_token(flow)
        email = _email_for_token(token)
        flow.response = _json_response(
            200,
            {"email": email, "name": DEFAULT_NAME},
        )
        return

    if url.startswith("https://www.googleapis.com/oauth2/v1/userinfo"):
        token = _extract_bearer_token(flow)
        email = _email_for_token(token)
        flow.response = _json_response(
            200,
            {"email": email, "name": DEFAULT_NAME},
        )
