"""
SCIM authentication middleware.

Uses the existing service account token system and requires super admin privileges.
"""

from functools import wraps

import flask

from middle_auth_client import auth_requires_admin

from .utils import build_error_response


def scim_auth_required(f):
    """
    Decorator for SCIM endpoints requiring authentication.
    
    Uses the existing service account token system via auth_requires_admin.
    Requires that the authenticated user/service account has super admin privileges.
    """
    
    @wraps(f)
    @auth_requires_admin
    def decorated_function(*args, **kwargs):
        # auth_requires_admin already validates authentication and admin status
        # It sets flask.g.auth_user and flask.g.auth_token
        
        # Verify we have a valid auth_user (should be guaranteed by auth_requires_admin)
        if not hasattr(flask.g, "auth_user") or not flask.g.auth_user:
            return build_error_response(
                401,
                "invalidCredentials",
                "Authentication required",
            )
        
        # Verify admin status (should be guaranteed by auth_requires_admin, but double-check)
        if not flask.g.auth_user.get("admin", False):
            return build_error_response(
                403,
                "insufficientRights",
                "SCIM access requires super admin privileges",
            )
        
        return f(*args, **kwargs)
    
    return decorated_function
