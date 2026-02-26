import requests
import os
from http.cookies import SimpleCookie

class WrappedSession(requests.Session):
    """A wrapper for requests.Session to override 'verify' property, ignoring REQUESTS_CA_BUNDLE environment variable.

    This is a workaround for https://github.com/kennethreitz/requests/issues/3829 (will be fixed in requests 3.0.0)
    """
    def merge_environment_settings(self, url, proxies, stream, verify, *args, **kwargs):
        if self.verify is not None:
            verify = self.verify

        return super(WrappedSession, self).merge_environment_settings(url, proxies, stream, verify, *args, **kwargs)
    
def combined_ca_bundle_path():
    combined_path = "/tmp/oauth_test_ca_bundle.pem"
    if os.path.exists(combined_path) and os.path.getsize(combined_path) > 0:
        return combined_path

    parts = []
    for path in (
        "/mitmproxy-certs/mitmproxy-ca-cert.pem",
        "/ssl-certs/middle-auth-server.crt",
    ):
        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, "r", encoding="utf-8") as file:
                parts.append(file.read())

    with open(combined_path, "w", encoding="utf-8") as out:
        out.write("\n".join(parts) + "\n")

    return combined_path

def token_from_set_cookie(set_cookie_header, token_name):
    if not set_cookie_header:
        return None
    cookie = SimpleCookie()
    cookie.load(set_cookie_header)
    morsel = cookie.get(token_name)
    return morsel.value if morsel else None
