import os
from playwright.sync_api import sync_playwright

_shared_email_file = os.environ.get("OAUTH_TEST_EMAIL_FILE", "/oauth-shared/test_email.txt")


def set_login_email(email):
    with open(_shared_email_file, "w", encoding="utf-8") as file:
        file.write(email)


def delete_login_email_file():
    if os.path.exists(_shared_email_file):
        os.remove(_shared_email_file)

def get_token_for_user(email):
    set_login_email(email)
    base_url = os.environ.get("MIDDLE_AUTH_BASE_URL", "http://localhost:5001/auth").rstrip("/")
    token_name = os.environ.get("TOKEN_NAME", "middle_auth_token")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context(ignore_https_errors=True)
            try:
                page = context.new_page()
                response = page.goto(f"{base_url}/api/v1/user/me") # any page should work
                if response is None or response.status != 200:
                    status = response.status if response is not None else "no-response"
                    raise RuntimeError(f"default admin login failed with status: {status}")

                delete_login_email_file()
                cookies = context.cookies([base_url])
                token_cookie = next(
                    (cookie for cookie in cookies if cookie.get("name") == token_name),
                    None,
                )
                if token_cookie is None or not token_cookie.get("value"):
                    raise RuntimeError(f"cookie '{token_name}' not found or empty")

                return token_cookie["value"]
            finally:
                context.close()
        finally:
            browser.close()