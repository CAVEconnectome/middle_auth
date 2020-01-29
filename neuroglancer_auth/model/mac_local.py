from functools import wraps
import flask
import json
import os
from urllib.parse import quote
from furl import furl
import requests

AUTH_URI = os.environ.get('AUTH_URI', 'localhost:5000/auth')
USE_REDIS = os.environ.get('AUTH_USE_REDIS', "false") == "true"

def get_user_cache(token):
    if USE_REDIS:
        print("USE REDIS")
        cached_user_data = r.get("token_" + token)
        if cached_user_data:
            return json.loads(cached_user_data.decode('utf-8'))
    else:
        print("DONT USE REDIS")
        pass
        # user_request = requests.get('https://' + AUTH_URI + '/user/me', headers={'authorization': 'Bearer ' + token})
        # if user_request.status_code == 200:
        #     return user_request.json()

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if hasattr(flask.g, 'auth_token'):
            # if authorization header has already been parsed, don't need to re-parse
            # this allows auth_required to be an optional decorator if auth_requires_role is also used
            return f(*args, **kwargs)

        token = None
        cookie_name = 'middle_auth_token'

        auth_header = flask.request.headers.get('authorization')
        xrw_header = flask.request.headers.get('X-Requested-With')

        programmatic_access = xrw_header or auth_header or flask.request.environ.get('HTTP_ORIGIN')

        if programmatic_access:
            if not auth_header:
                resp = flask.Response("Unauthorized", 401)
                resp.headers['WWW-Authenticate'] = 'Bearer realm="' + AUTH_URI + '"'
                return resp
            elif not auth_header.startswith('Bearer '):
                resp = flask.Response("Invalid Request", 400)
                resp.headers['WWW-Authenticate'] = 'Bearer realm="' + AUTH_URI + '", error="invalid_request", error_description="Header must begin with \'Bearer\'"'
                return resp

            token = auth_header.split(' ')[1] # remove schema
        else: # direct browser access, or a non-browser request missing auth header (user error) TODO: check user agent to deliver 401 in this case
            query_param_token = flask.request.args.get('token')

            if query_param_token:
                resp = flask.make_response(flask.redirect(furl(flask.request.url).remove(['token']).url, code=302))
                resp.set_cookie(cookie_name, query_param_token, secure=True, httponly=True)
                return resp

            token = flask.request.cookies.get(cookie_name)

        user_request = requests.get('https://' + AUTH_URI + '/user/me', headers={'authorization': auth_header})

        cached_user_data = get_user_cache(token) if token else None

        if cached_user_data:
            flask.g.auth_user = cached_user_data
            flask.g.auth_token = token
            return f(*args, **kwargs)
        elif not programmatic_access:
            return flask.redirect('https://' + AUTH_URI + '/authorize?redirect=' + quote(flask.request.url), code=302)
        else:
            resp = flask.Response("Invalid/Expired Token", 401)
            resp.headers['WWW-Authenticate'] = 'Bearer realm="' + AUTH_URI + '", error="invalid_token", error_description="Invalid/Expired Token"'
            return resp
    return decorated_function


def auth_requires_admin(f):
    @wraps(f)
    @auth_required
    def decorated_function(*args, **kwargs):
        if not flask.g.auth_user['admin']:
            resp = flask.Response("Requires superadmin privilege.", 403)
            return resp
        else:
            return f(*args, **kwargs)

    return decorated_function


def auth_requires_permission(required_permission):
    def decorator(f):
        @wraps(f)
        @auth_required
        def decorated_function(table_id, *args, **kwargs):
            required_level = ['none', 'view', 'edit'].index(required_permission)

            table_id_to_dataset = {
                "pinky100_sv16": "pinky100",
                "pinky100_neo1": "pinky100",
                "fly_v26": "fafb_sandbox",
                "fly_v31": "fafb",
            }

            if table_id in table_id_to_dataset:
                dataset = table_id_to_dataset.get(table_id)
            else:
                if table_id.startswith("pinky100_rv") or \
                        table_id.startswith("pinky100_arv"):
                    dataset = "pinky100"
                else:
                    raise Exception("Unknown dataset")

            if dataset is not None:
                level_for_dataset = flask.g.auth_user['permissions'].get(dataset, 0)
                has_permission = level_for_dataset >= required_level

                if has_permission:
                    return f(*args, **{**kwargs, **{'table_id': table_id}})
                else:
                    resp = flask.Response("Missing permission: {0} for dataset {1}".format(required_permission, dataset), 403)
                    return resp
            else:
                resp = flask.Response("Invalid table_id", 400)
                return resp

        return decorated_function
    return decorator