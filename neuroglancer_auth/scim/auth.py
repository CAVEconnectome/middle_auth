"""
SCIM authentication middleware.

Uses the existing service account token system and requires super admin privileges.
Returns SCIM-compliant error responses for authentication failures.

This decorator intercepts authentication errors BEFORE auth_required processes them,
ensuring all auth failures return SCIM-compliant 401 errors.
"""

from functools import wraps

import flask

from middle_auth_client import auth_required

from .utils import build_error_response


def scim_auth_required(f):
    """
    Decorator for SCIM endpoints requiring authentication.
    
    Uses the existing service account token system via auth_required.
    Requires that the authenticated user/service account has super admin privileges.
    Returns SCIM-compliant 401/403 error responses.
    
    This decorator intercepts authentication errors BEFORE auth_required processes them
    to ensure SCIM-compliant error formatting (RFC 7644 §3.12).
    """
    
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Intercept Authorization header check BEFORE auth_required runs
        # This handles the case where auth_required returns 400 for malformed headers
        auth_header = flask.request.headers.get("authorization")
        
        if auth_header:
            # If Authorization header exists but doesn't start with "Bearer ", 
            # auth_required will return 400. We intercept this and return SCIM 401 instead.
            if not auth_header.startswith("Bearer "):
                return build_error_response(
                    401,
                    "invalidCredentials",
                    "Authentication required",
                )
        
        # Now apply auth_required - it will handle other cases (no header, invalid token, etc.)
        @auth_required
        def auth_decorated(*args, **kwargs):
            # If we get here, authentication succeeded
            # Now check for admin status
            if not hasattr(flask.g, "auth_user") or not flask.g.auth_user:
                return build_error_response(
                    401,
                    "invalidCredentials",
                    "Authentication required",
                )
            
            # Verify admin status (required for SCIM access)
            if not flask.g.auth_user.get("admin", False):
                return build_error_response(
                    403,
                    "insufficientRights",
                    "SCIM access requires super admin privileges",
                )
            
            return f(*args, **kwargs)
        
        try:
            result = auth_decorated(*args, **kwargs)
            
            # Check if result is an error response that needs SCIM formatting
            if isinstance(result, flask.Response):
                status_code = result.status_code
                
                # If it's an auth error (400/401/403), ensure it's SCIM-formatted
                if status_code in [400, 401, 403]:
                    # Check if already SCIM-formatted
                    try:
                        import json
                        content_type = result.headers.get("Content-Type", "")
                        if "application/scim+json" in content_type:
                            # Already SCIM-formatted, return as-is
                            return result
                        
                        # Try to parse response body
                        data = json.loads(result.get_data(as_text=True))
                        if "schemas" in data and "urn:ietf:params:scim:api:messages:2.0:Error" in data.get("schemas", []):
                            # Already SCIM-formatted
                            return result
                    except (json.JSONDecodeError, ValueError, AttributeError):
                        pass
                    
                    # Convert to SCIM format
                    if status_code == 400 or status_code == 401:
                        # Authentication error - return 401 in SCIM format
                        return build_error_response(
                            401,
                            "invalidCredentials",
                            "Authentication required",
                        )
                    elif status_code == 403:
                        # Authorization error
                        return build_error_response(
                            403,
                            "insufficientRights",
                            "SCIM access requires super admin privileges",
                        )
            
            return result
            
        except Exception:
            # If any exception occurs during auth, return SCIM 401
            return build_error_response(
                401,
                "invalidCredentials",
                "Authentication required",
            )
    
    return wrapper
