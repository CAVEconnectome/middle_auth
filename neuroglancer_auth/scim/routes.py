"""
SCIM 2.0 API routes.

Implements SCIM 2.0 endpoints for Users, Groups, and Datasets (custom resource type).
"""

import re
import os
import flask
import sqlalchemy
from ..model.dataset import Dataset
from ..model.dataset_admin import DatasetAdmin
from ..model.group import Group
from ..model.group_dataset_permission import GroupDatasetPermission
from ..model.permission import Permission
from ..model.table_mapping import ServiceTable
from ..model.user import User
from ..model.user_group import UserGroup
from .auth import scim_auth_required
from .filter import SCIMFilterError, SCIMFilterParser
from .serializers import (
    DatasetSCIMSerializer,
    GroupSCIMSerializer,
    UserSCIMSerializer,
)
from .utils import (
    build_error_response,
    build_list_response,
    create_dataset_with_scim,
    create_group_with_scim,
    create_user_with_scim,
    find_dataset_by_scim_identifier,
    find_group_by_scim_identifier,
    find_user_by_scim_identifier,
    format_datetime,
    generate_scim_id,
    get_base_url,
    parse_pagination_params,
    SCIMPaginationError,
)

URL_PREFIX = os.environ.get("URL_PREFIX", "auth")

# Create SCIM blueprint
scim_bp = flask.Blueprint("scim_bp", __name__, url_prefix="/" + URL_PREFIX + "/scim/v2")


def extract_identifier_from_path_filter(path: str) -> str:
    """
    Extract identifier from SCIM path filter expression.
    
    For paths like 'members[value eq "some-uuid"]', extracts 'some-uuid'.
    For paths like 'groups[value eq "group-id"]', extracts 'group-id'.
    
    Args:
        path: SCIM path with optional filter expression
        
    Returns:
        Extracted identifier string, or None if no filter found
    """
    # Match pattern like: attributeName[value eq "identifier"]
    match = re.search(r'\[value\s+eq\s+"([^"]+)"\]', path)
    if match:
        return match.group(1)
    
    # Also handle single quotes
    match = re.search(r"\[value\s+eq\s+'([^']+)'\]", path)
    if match:
        return match.group(1)
    
    return None


# ============================================================================
# Discovery Endpoints
# ============================================================================


@scim_bp.route("/ServiceProviderConfig", methods=["GET"])
@scim_auth_required
def service_provider_config():
    """SCIM Service Provider Configuration endpoint."""
    base_url = get_base_url()
    
    response = flask.jsonify(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 1000},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": True},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": "Authentication using OAuth Bearer Token",
                }
            ],
            "meta": {
                "location": f"{base_url}/v2/ServiceProviderConfig",
                "resourceType": "ServiceProviderConfig",
            },
        }
    )
    response.headers["Content-Type"] = "application/scim+json"
    return response


@scim_bp.route("/ResourceTypes", methods=["GET"])
@scim_auth_required
def resource_types():
    """SCIM Resource Types endpoint."""
    base_url = get_base_url()
    
    resource_types = [
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/v2/Users",
            "description": "User account",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
            "schemaExtensions": [
                {
                    "schema": "urn:ietf:params:scim:schemas:extension:neuroglancer:2.0:User",
                    "required": False,
                }
            ],
            "meta": {
                "location": f"{base_url}/v2/ResourceTypes/User",
                "resourceType": "ResourceType",
            },
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/v2/Groups",
            "description": "Group",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
            "schemaExtensions": [
                {
                    "schema": "urn:ietf:params:scim:schemas:neuroglancer:2.0:GroupPermissions",
                    "required": False,
                }
            ],
            "meta": {
                "location": f"{base_url}/v2/ResourceTypes/Group",
                "resourceType": "ResourceType",
            },
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Dataset",
            "name": "Dataset",
            "endpoint": "/v2/Datasets",
            "description": "Dataset resource representing data collections",
            "schema": "urn:ietf:params:scim:schemas:neuroglancer:2.0:Dataset",
            "meta": {
                "location": f"{base_url}/v2/ResourceTypes/Dataset",
                "resourceType": "ResourceType",
            },
        },
    ]
    
    response = flask.jsonify(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(resource_types),
            "Resources": resource_types,
        }
    )
    response.headers["Content-Type"] = "application/scim+json"
    return response


@scim_bp.route("/Schemas", methods=["GET"])
@scim_auth_required
def schemas():
    """SCIM Schemas endpoint."""
    base_url = get_base_url()
    
    # Return list of available schemas
    schemas_list = [
        {
            "id": "urn:ietf:params:scim:schemas:core:2.0:User",
            "name": "User",
            "description": "User Account",
            "attributes": [
                {
                    "name": "id",
                    "type": "string",
                    "multiValued": False,
                    "required": True,
                    "caseExact": False,
                    "mutability": "readOnly",
                    "returned": "default",
                    "uniqueness": "server",
                },
                {
                    "name": "userName",
                    "type": "string",
                    "multiValued": False,
                    "required": True,
                    "caseExact": False,
                    "mutability": "readWrite",
                    "returned": "default",
                    "uniqueness": "server",
                },
                {
                    "name": "name",
                    "type": "complex",
                    "multiValued": False,
                    "required": False,
                    "mutability": "readWrite",
                    "returned": "default",
                    "subAttributes": [
                        {"name": "givenName", "type": "string"},
                        {"name": "familyName", "type": "string"},
                        {"name": "formatted", "type": "string"},
                    ],
                },
                {
                    "name": "emails",
                    "type": "complex",
                    "multiValued": True,
                    "required": False,
                    "mutability": "readWrite",
                    "returned": "default",
                    "subAttributes": [
                        {"name": "value", "type": "string"},
                        {"name": "type", "type": "string"},
                        {"name": "primary", "type": "boolean"},
                    ],
                },
            ],
            "meta": {
                "location": f"{base_url}/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User",
                "resourceType": "Schema",
            },
        },
        {
            "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
            "name": "Group",
            "description": "Group",
            "attributes": [
                {
                    "name": "id",
                    "type": "string",
                    "multiValued": False,
                    "required": True,
                    "caseExact": False,
                    "mutability": "readOnly",
                    "returned": "default",
                    "uniqueness": "server",
                },
                {
                    "name": "displayName",
                    "type": "string",
                    "multiValued": False,
                    "required": True,
                    "caseExact": False,
                    "mutability": "readWrite",
                    "returned": "default",
                    "uniqueness": "server",
                },
                {
                    "name": "members",
                    "type": "complex",
                    "multiValued": True,
                    "required": False,
                    "mutability": "readWrite",
                    "returned": "default",
                    "subAttributes": [
                        {"name": "value", "type": "string"},
                        {"name": "$ref", "type": "reference"},
                        {"name": "display", "type": "string"},
                    ],
                },
            ],
            "meta": {
                "location": f"{base_url}/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group",
                "resourceType": "Schema",
            },
        },
        {
            "id": "urn:ietf:params:scim:schemas:neuroglancer:2.0:Dataset",
            "name": "Dataset",
            "description": "Dataset resource",
            "attributes": [
                {
                    "name": "id",
                    "type": "string",
                    "multiValued": False,
                    "required": True,
                    "mutability": "readOnly",
                },
                {
                    "name": "name",
                    "type": "string",
                    "multiValued": False,
                    "required": True,
                    "mutability": "readWrite",
                },
                {
                    "name": "tosId",
                    "type": "integer",
                    "multiValued": False,
                    "required": False,
                    "mutability": "readWrite",
                },
                {
                    "name": "serviceTables",
                    "type": "complex",
                    "multiValued": True,
                    "required": False,
                    "mutability": "readWrite",
                    "subAttributes": [
                        {"name": "serviceName", "type": "string"},
                        {"name": "tableName", "type": "string"},
                        {"name": "datasetId", "type": "string"},
                    ],
                },
            ],
            "meta": {
                "location": f"{base_url}/v2/Schemas/urn:ietf:params:scim:schemas:neuroglancer:2.0:Dataset",
                "resourceType": "Schema",
            },
        },
    ]
    
    response = flask.jsonify(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(schemas_list),
            "Resources": schemas_list,
        }
    )
    response.headers["Content-Type"] = "application/scim+json"
    return response


@scim_bp.route("/Schemas/<schema_id>", methods=["GET"])
@scim_auth_required
def get_schema(schema_id):
    """Get specific schema by ID."""
    # For now, return 404 - full schema definitions would be here
    return build_error_response(404, "NOT_FOUND", f"Schema {schema_id} not found")


# ============================================================================
# User Endpoints
# ============================================================================


@scim_bp.route("/Users", methods=["GET"])
@scim_auth_required
def list_users():
    """List/search Users."""
    # Parse pagination
    try:
        start_index, count = parse_pagination_params()
    except SCIMPaginationError as e:
        return build_error_response(
            400,
            "invalidValue",
            str(e)
        )
    
    # Parse filter
    filter_expr = flask.request.args.get("filter")
    
    # Build query
    query = User.query.filter(User.parent_id.is_(None))  # Exclude service accounts
    
    # Apply filter
    if filter_expr:
        try:
            query = SCIMFilterParser.apply_user_filter(query, filter_expr)
        except SCIMFilterError as e:
            return build_error_response(
                400,
                "invalidFilter",
                f"Invalid filter expression: {str(e)}"
            )
    
    # Get total count
    total_results = query.count()
    
    # Apply pagination (SCIM uses 1-based indexing)
    offset = start_index - 1
    users = query.offset(offset).limit(count).all()
    
    # Serialize
    resources = [UserSCIMSerializer.to_scim(user) for user in users]
    
    # Build response
    response_data = build_list_response(resources, total_results, start_index, len(resources))
    response = flask.jsonify(response_data)
    response.headers["Content-Type"] = "application/scim+json"
    return response


@scim_bp.route("/Users/<scim_id>", methods=["GET"])
@scim_auth_required
def get_user(scim_id):
    """Get specific User by SCIM ID."""
    # Lookup by scim_id (uses indexed column for O(1) lookup)
    user = find_user_by_scim_identifier(scim_id=scim_id)
    
    if user:
        resource = UserSCIMSerializer.to_scim(user)
        response = flask.jsonify(resource)
        response.headers["Content-Type"] = "application/scim+json"
        return response
    
    return build_error_response(404, "NOT_FOUND", f"User {scim_id} not found")


def _sanitize_pi_field(pi_value):
    """
    Sanitize pi field value to prevent IntegrityError.
    
    The pi column is nullable=False with server_default="", so passing None
    would override the server default and cause an IntegrityError.
    
    Args:
        pi_value: The pi value from user_data (can be None, empty string, or a string)
        
    Returns:
        Empty string if pi_value is None, otherwise returns pi_value as-is
    """
    return "" if pi_value is None else pi_value


@scim_bp.route("/Users", methods=["POST"])
@scim_auth_required
def create_user():
    """Create new User."""
    data = flask.request.get_json()
    
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Convert SCIM to internal format
    user_data = UserSCIMSerializer.from_scim(data)
    
    # Validate required fields
    if "email" not in user_data:
        return build_error_response(400, "invalidValue", "userName or emails[0].value required")
    
    if "name" not in user_data:
        return build_error_response(400, "invalidValue", "name or displayName required")
    
    # SCIM 2.0 RFC 7644: POST is NOT idempotent - always return 409 Conflict if resource exists
    # Check for existing user by externalId (if provided) or email
    existing_user = None
    
    # Check by externalId first (if provided)
    if "external_id" in user_data and user_data["external_id"]:
        existing_user = User.query.filter_by(external_id=user_data["external_id"]).first()
        if existing_user:
            return build_error_response(
                409,
                "uniqueness",
                f"User with externalId '{user_data['external_id']}' already exists.",
            )
    
    # Check by email
    existing_user = User.get_by_email(user_data["email"])
    if existing_user:
        return build_error_response(
            409,
            "uniqueness",
            f"User with email '{user_data['email']}' already exists. "
            "Search for the user first, then use PATCH to update externalId to link it.",
        )
    
    # User doesn't exist, create new one
    try:
        user = create_user_with_scim(
            email=user_data["email"],
            name=user_data.get("name", ""),
            pi=_sanitize_pi_field(user_data.get("pi")),
            admin=user_data.get("admin", False),
            gdpr_consent=user_data.get("gdpr_consent", False),
            group_names=["default"],
            external_id=user_data.get("external_id"),
        )
        
        # Serialize and return
        resource = UserSCIMSerializer.to_scim(user)
        response = flask.jsonify(resource)
        response.status_code = 201  # Created
        response.headers["Content-Type"] = "application/scim+json"
        response.headers["Location"] = resource["meta"]["location"]
        return response
        
    except sqlalchemy.exc.IntegrityError as e:
        # Rollback invalid session state before querying
        from ..model.base import db
        db.session.rollback()
        
        # Check if this is actually a duplicate email/external_id race condition
        # by checking if the user now exists
        existing_user = None
        if "external_id" in user_data and user_data["external_id"]:
            existing_user = User.query.filter_by(external_id=user_data["external_id"]).first()
        if not existing_user:
            existing_user = User.get_by_email(user_data["email"])
        
        if existing_user:
            # This was a race condition: user was created between our check and creation
            # Return 409 Conflict per SCIM spec (POST is not idempotent)
            return build_error_response(
                409,
                "uniqueness",
                f"User with email '{user_data['email']}' already exists.",
            )
        
        # If still not found, this might be a different IntegrityError (e.g., NULL constraint)
        # Check the error message to provide better feedback
        error_msg = str(e.orig) if hasattr(e, 'orig') else str(e)
        if "NOT NULL" in error_msg or "null value" in error_msg.lower():
            return build_error_response(
                400,
                "invalidValue",
                f"Required field constraint violation: {error_msg}",
            )
        
        # Generic conflict error for other IntegrityErrors
        return build_error_response(409, "uniqueness", "User already exists")


@scim_bp.route("/Users/<scim_id>", methods=["PUT"])
@scim_auth_required
def replace_user(scim_id):
    """Replace User (full update)."""
    # Find user by scim_id
    user = find_user_by_scim_identifier(scim_id=scim_id)
    
    if not user:
        return build_error_response(404, "NOT_FOUND", f"User {scim_id} not found")
    
    data = flask.request.get_json()
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Convert SCIM to internal format
    user_data = UserSCIMSerializer.from_scim(data)
    
    from ..model.base import db
    
    # Update external_id if provided (set but don't commit yet - will be committed with other updates)
    if "external_id" in user_data:
        user.external_id = user_data["external_id"]
    
    # Update user (remove external_id from update_data as it's handled separately)
    # Also sanitize pi field to prevent IntegrityError if it's None
    update_data = {k: v for k, v in user_data.items() if k != "external_id"}
    if "pi" in update_data:
        update_data["pi"] = _sanitize_pi_field(update_data["pi"])
    
    try:
        # Apply all updates atomically
        # user.update() commits internally, so if it succeeds, external_id is also committed
        # If it fails, we rollback everything including external_id
        if update_data:
            user.update(update_data)
        elif "external_id" in user_data:
            # If only external_id was updated, commit it now
            db.session.commit()
        
        # Serialize and return
        resource = UserSCIMSerializer.to_scim(user)
        response = flask.jsonify(resource)
        response.headers["Content-Type"] = "application/scim+json"
        return response
        
    except sqlalchemy.exc.IntegrityError as e:
        # Rollback all changes (including external_id) if any update fails
        # This ensures transaction atomicity - either all updates succeed or none do
        db.session.rollback()
        
        # Check if this is a duplicate email error
        if "email" in update_data:
            existing_user = User.get_by_email(update_data["email"])
            if existing_user and existing_user.id != user.id:
                return build_error_response(
                    409,
                    "uniqueness",
                    f"User with email '{update_data['email']}' already exists.",
                )
        
        # Check for other IntegrityError cases (e.g., NULL constraint)
        error_msg = str(e.orig) if hasattr(e, 'orig') else str(e)
        if "NOT NULL" in error_msg or "null value" in error_msg.lower():
            return build_error_response(
                400,
                "invalidValue",
                f"Required field constraint violation: {error_msg}",
            )
        
        # Generic conflict error for other IntegrityErrors
        return build_error_response(409, "uniqueness", "User update failed due to constraint violation")
        
    except Exception as e:
        # Rollback all changes (including external_id) if any update fails
        # This ensures transaction atomicity - either all updates succeed or none do
        db.session.rollback()
        return build_error_response(400, "invalidValue", str(e))


# Helper functions for User PATCH operations
def _handle_user_replace(user, path, value):
    """Handle replace operation for User."""
    if path == "userName" or path.startswith("emails["):
        email_value = value.get("value", value) if isinstance(value, dict) else value
        # Check for duplicate email before updating
        existing_user = User.get_by_email(email_value)
        if existing_user and existing_user.id != user.id:
            raise ValueError(f"User with email '{email_value}' already exists.")
        user.email = email_value
    elif path == "name.givenName" or path == "name.familyName" or path == "displayName":
        # Update name
        if isinstance(value, dict):
            name = f"{value.get('givenName', '')} {value.get('familyName', '')}".strip()
        else:
            name = value
        user.name = name
    elif path == "externalId":
        # Update external_id
        external_id = value.get("value", value) if isinstance(value, dict) else value
        user.external_id = external_id if external_id else None
    elif isinstance(value, dict):
        # Direct value update
        user_data = UserSCIMSerializer.from_scim({"schemas": [], **value})
        # Sanitize pi field to prevent IntegrityError if it's None
        if "pi" in user_data:
            user_data["pi"] = _sanitize_pi_field(user_data["pi"])
        # Check for duplicate email before updating
        if "email" in user_data:
            existing_user = User.get_by_email(user_data["email"])
            if existing_user and existing_user.id != user.id:
                raise ValueError(f"User with email '{user_data['email']}' already exists.")
        # Apply updates directly to user object
        for field, field_value in user_data.items():
            if hasattr(user, field):
                setattr(user, field, field_value)


def _handle_user_add(user, path, value):
    """Handle add operation for User."""
    from ..model.base import db
    
    if path.startswith("groups[") or path == "groups":
        # Add user to group
        groups_to_add = []
        if path == "groups":
            # Value is array of groups
            if isinstance(value, list):
                for group_item in value:
                    group_scim_id = group_item.get("value") if isinstance(group_item, dict) else group_item
                    group = find_group_by_scim_identifier(scim_id=group_scim_id)
                    if group:
                        groups_to_add.append(group)
        else:
            # Single group in path like "groups[value eq \"...\"]" or direct value
            group_scim_id = value.get("value") if isinstance(value, dict) else value
            group = find_group_by_scim_identifier(scim_id=group_scim_id)
            if group:
                groups_to_add.append(group)
        
        # Add all groups (check for duplicates first)
        for group in groups_to_add:
            existing_ug = UserGroup.get(group.id, user.id)
            if not existing_ug:
                ug = UserGroup(user_id=user.id, group_id=group.id)
                db.session.add(ug)


def _handle_user_remove(user, path, value):
    """Handle remove operation for User."""
    from ..model.base import db
    
    if path.startswith("groups[") or path == "groups":
        # Remove user from group
        groups_to_remove = []
        if path == "groups":
            # Value is array of groups to remove
            if isinstance(value, list):
                for group_item in value:
                    group_scim_id = group_item.get("value") if isinstance(group_item, dict) else group_item
                    group = find_group_by_scim_identifier(scim_id=group_scim_id)
                    if group:
                        groups_to_remove.append(group)
        else:
            # Path contains filter expression like "groups[value eq \"...\"]"
            # Extract identifier from path filter (RFC 7644: remove with filter has no value field)
            group_scim_id = extract_identifier_from_path_filter(path)
            if not group_scim_id:
                # Fallback: try to get from value if provided (for backward compatibility)
                group_scim_id = value.get("value") if isinstance(value, dict) else value
            
            if group_scim_id:
                group = find_group_by_scim_identifier(scim_id=group_scim_id)
                if group:
                    groups_to_remove.append(group)
        
        # Remove all groups
        for group in groups_to_remove:
            ug = UserGroup.get(group.id, user.id)
            if ug:
                db.session.delete(ug)


@scim_bp.route("/Users/<scim_id>", methods=["PATCH"])
@scim_auth_required
def patch_user(scim_id):
    """Partial update User."""
    from ..model.base import db
    
    # Find user by scim_id
    user = find_user_by_scim_identifier(scim_id=scim_id)
    
    if not user:
        return build_error_response(404, "NOT_FOUND", f"User {scim_id} not found")
    
    data = flask.request.get_json()
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Handle PATCH operations atomically - all succeed or all fail
    operations = data.get("Operations", [])
    
    try:
        for op in operations:
            op_type = op.get("op")
            path = op.get("path", "")
            value = op.get("value")
            
            if op_type == "replace":
                _handle_user_replace(user, path, value)
            elif op_type == "add":
                _handle_user_add(user, path, value)
            elif op_type == "remove":
                _handle_user_remove(user, path, value)
        
        # Commit all changes atomically
        db.session.commit()
        
        # Update cache after all changes are committed
        user.update_cache()
        
    except ValueError as e:
        # Validation error (e.g., duplicate email)
        db.session.rollback()
        error_msg = str(e)
        if "already exists" in error_msg:
            return build_error_response(409, "uniqueness", error_msg)
        return build_error_response(400, "invalidValue", error_msg)
    except sqlalchemy.exc.IntegrityError as e:
        # Database integrity error
        db.session.rollback()
        error_msg = str(e.orig) if hasattr(e, 'orig') else str(e)
        if "email" in error_msg.lower() or "unique" in error_msg.lower():
            return build_error_response(409, "uniqueness", "A user with this email already exists.")
        return build_error_response(400, "invalidValue", f"Database constraint violation: {error_msg}")
    except Exception as e:
        # Any other error - rollback and return error
        db.session.rollback()
        return build_error_response(400, "invalidValue", str(e))
    
    # Serialize and return
    resource = UserSCIMSerializer.to_scim(user)
    response = flask.jsonify(resource)
    response.headers["Content-Type"] = "application/scim+json"
    return response


@scim_bp.route("/Users/<scim_id>", methods=["DELETE"])
@scim_auth_required
def delete_user(scim_id):
    """Delete User."""
    # Find user by scim_id
    user = find_user_by_scim_identifier(scim_id=scim_id)
    
    if not user:
        return build_error_response(404, "NOT_FOUND", f"User {scim_id} not found")
    
    # Delete using existing method
    User.delete_user_account(user.id)
    
    return flask.Response(status=204)


# ============================================================================
# Group Endpoints
# ============================================================================


@scim_bp.route("/Groups", methods=["GET"])
@scim_auth_required
def list_groups():
    """List/search Groups."""
    # Parse pagination
    try:
        start_index, count = parse_pagination_params()
    except SCIMPaginationError as e:
        return build_error_response(
            400,
            "invalidValue",
            str(e)
        )
    
    # Parse filter
    filter_expr = flask.request.args.get("filter")
    
    # Build query
    query = Group.query
    
    # Apply filter
    if filter_expr:
        try:
            query = SCIMFilterParser.apply_group_filter(query, filter_expr)
        except SCIMFilterError as e:
            return build_error_response(
                400,
                "invalidFilter",
                f"Invalid filter expression: {str(e)}"
            )
    
    # Get total count
    total_results = query.count()
    
    # Apply pagination
    offset = start_index - 1
    groups = query.offset(offset).limit(count).all()
    
    # Serialize
    resources = [GroupSCIMSerializer.to_scim(group, include_members=False, include_permissions=False) for group in groups]
    
    # Build response
    response_data = build_list_response(resources, total_results, start_index, len(resources))
    response = flask.jsonify(response_data)
    response.headers["Content-Type"] = "application/scim+json"
    return response


@scim_bp.route("/Groups/<scim_id>", methods=["GET"])
@scim_auth_required
def get_group(scim_id):
    """Get specific Group by SCIM ID."""
    # Find group by scim_id
    group = find_group_by_scim_identifier(scim_id=scim_id)
    
    if group:
        resource = GroupSCIMSerializer.to_scim(group)
        response = flask.jsonify(resource)
        response.headers["Content-Type"] = "application/scim+json"
        return response
    
    return build_error_response(404, "NOT_FOUND", f"Group {scim_id} not found")


@scim_bp.route("/Groups", methods=["POST"])
@scim_auth_required
def create_group():
    """Create new Group."""
    data = flask.request.get_json()
    
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Convert SCIM to internal format
    group_data = GroupSCIMSerializer.from_scim(data)
    
    # Validate required fields
    if "name" not in group_data:
        return build_error_response(400, "invalidValue", "displayName required")
    
    # SCIM 2.0 RFC 7644: POST is NOT idempotent - always return 409 Conflict if resource exists
    # Check for existing group by externalId (if provided) or name
    existing_group = None
    
    # Check by externalId first (if provided)
    if "external_id" in group_data and group_data["external_id"]:
        existing_group = Group.query.filter_by(external_id=group_data["external_id"]).first()
        if existing_group:
            return build_error_response(
                409,
                "uniqueness",
                f"Group with externalId '{group_data['external_id']}' already exists.",
            )
    
    # Check by name
    existing_group = Group.query.filter_by(name=group_data["name"]).first()
    if existing_group:
        return build_error_response(
            409,
            "uniqueness",
            f"Group with name '{group_data['name']}' already exists. "
            "Search for the group first, then use PATCH to update externalId to link it.",
        )
    
    # Group doesn't exist, create new one
    try:
        group = create_group_with_scim(
            name=group_data["name"],
            external_id=group_data.get("external_id"),
        )
        
        # Handle members if provided
        members = data.get("members", [])
        for member in members:
            member_scim_id = member.get("value")
            member_user = find_user_by_scim_identifier(scim_id=member_scim_id)
            if member_user:
                try:
                    UserGroup.add(member_user.id, group.id)
                    member_user.update_cache()
                except sqlalchemy.exc.IntegrityError:
                    pass  # Already in group
        
        # Handle permissions if provided
        permissions_ext = data.get(
            "urn:ietf:params:scim:schemas:neuroglancer:2.0:GroupPermissions", {}
        )
        dataset_perms = permissions_ext.get("datasetPermissions", [])
        for dp in dataset_perms:
            if isinstance(dp, dict):
                dataset_scim_id = dp.get("datasetId")
                permission_names = dp.get("permissions", [])
                
                dataset = find_dataset_by_scim_identifier(scim_id=dataset_scim_id)
                if not dataset:
                    continue
                
                # Map permission names to IDs
                permission_ids = []
                for perm_name in permission_names:
                    perm = Permission.query.filter_by(name=perm_name).first()
                    if perm:
                        permission_ids.append(perm.id)
                
                # Add permissions
                if permission_ids:
                    try:
                        GroupDatasetPermission.add(
                            group_id=group.id,
                            dataset_id=dataset.id,
                            permission_ids=permission_ids
                        )
                    except sqlalchemy.exc.IntegrityError:
                        pass  # Permission already exists
        
        group.update_cache()  # Update cache after all changes
        
        # Serialize and return
        resource = GroupSCIMSerializer.to_scim(group)
        response = flask.jsonify(resource)
        response.status_code = 201
        response.headers["Content-Type"] = "application/scim+json"
        response.headers["Location"] = resource["meta"]["location"]
        return response
        
    except sqlalchemy.exc.IntegrityError:
        # Race condition: group was created between our check and creation
        # Return 409 Conflict per SCIM spec (POST is not idempotent)
        from ..model.base import db
        db.session.rollback()  # Rollback invalid session state before querying
        existing_group = Group.query.filter_by(name=group_data["name"]).first()
        if existing_group:
            return build_error_response(
                409,
                "uniqueness",
                f"Group with name '{group_data['name']}' already exists.",
            )
        # If still not found, return generic conflict error
        return build_error_response(409, "uniqueness", "Group already exists")


@scim_bp.route("/Groups/<scim_id>", methods=["PUT"])
@scim_auth_required
def replace_group(scim_id):
    """Replace Group (full update)."""
    from ..model.base import db
    
    # Find group by scim_id
    group = find_group_by_scim_identifier(scim_id=scim_id)
    
    if not group:
        return build_error_response(404, "NOT_FOUND", f"Group {scim_id} not found")
    
    data = flask.request.get_json()
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Convert SCIM to internal format
    group_data = GroupSCIMSerializer.from_scim(data)
    
    # Track affected users for cache updates (after commit)
    affected_users = set()
    
    try:
        # Update group (Group model doesn't have update method, so update directly)
        if "name" in group_data:
            group.name = group_data["name"]
        if "external_id" in group_data:
            group.external_id = group_data["external_id"]
        
        # Handle members - PUT is full replace, so replace all members
        if "members" in data:
            # Get affected users before deletion
            existing_members = UserGroup.query.filter_by(group_id=group.id).all()
            for member in existing_members:
                affected_users.add(member.user_id)
            
            # Remove all existing members (don't commit yet)
            UserGroup.query.filter_by(group_id=group.id).delete()
            
            # Add new members from request (use direct session operations)
            members = data.get("members", [])
            for member in members:
                member_scim_id = member.get("value")
                member_user = find_user_by_scim_identifier(scim_id=member_scim_id)
                if member_user:
                    # Check if already exists (shouldn't happen after delete, but check anyway)
                    existing_ug = UserGroup.get(group.id, member_user.id)
                    if not existing_ug:
                        ug = UserGroup(user_id=member_user.id, group_id=group.id)
                        db.session.add(ug)
                        affected_users.add(member_user.id)
        
        # Handle permissions - PUT is full replace, so replace all permissions
        permissions_ext = data.get(
            "urn:ietf:params:scim:schemas:neuroglancer:2.0:GroupPermissions", {}
        )
        if permissions_ext or "urn:ietf:params:scim:schemas:neuroglancer:2.0:GroupPermissions" in data.get("schemas", []):
            # Remove all existing permissions for this group (don't commit yet)
            GroupDatasetPermission.query.filter_by(group_id=group.id).delete()
            
            # Add new permissions from request (use direct session operations)
            dataset_perms = permissions_ext.get("datasetPermissions", [])
            for dp in dataset_perms:
                if isinstance(dp, dict):
                    dataset_scim_id = dp.get("datasetId")
                    permission_names = dp.get("permissions", [])
                    
                    dataset = find_dataset_by_scim_identifier(scim_id=dataset_scim_id)
                    if not dataset:
                        continue
                    
                    # Map permission names to IDs
                    permission_ids = []
                    for perm_name in permission_names:
                        perm = Permission.query.filter_by(name=perm_name).first()
                        if perm:
                            permission_ids.append(perm.id)
                    
                    # Add permissions directly to session
                    for perm_id in permission_ids:
                        gd = GroupDatasetPermission(
                            group_id=group.id,
                            dataset_id=dataset.id,
                            permission_id=perm_id
                        )
                        db.session.add(gd)
        
        # Commit all changes atomically
        db.session.commit()
        
        # Update caches after all changes are committed
        for user_id in affected_users:
            user = User.get_by_id(user_id)
            if user:
                user.update_cache()
        group.update_cache()
        
    except sqlalchemy.exc.IntegrityError as e:
        # Database integrity error
        db.session.rollback()
        error_msg = str(e.orig) if hasattr(e, 'orig') else str(e)
        if "unique" in error_msg.lower() or "duplicate" in error_msg.lower():
            return build_error_response(409, "uniqueness", "A constraint violation occurred.")
        return build_error_response(400, "invalidValue", f"Database constraint violation: {error_msg}")
    except Exception as e:
        # Any other error - rollback and return error
        db.session.rollback()
        return build_error_response(400, "invalidValue", str(e))
    
    # Serialize and return
    resource = GroupSCIMSerializer.to_scim(group)
    response = flask.jsonify(resource)
    response.headers["Content-Type"] = "application/scim+json"
    return response


# Helper functions for Group PATCH operations
def _handle_group_replace(group, path, value):
    """Handle replace operation for Group."""
    from ..model.base import db
    
    if path == "displayName":
        group.name = value
    elif path == "externalId":
        # Update external_id
        external_id = value.get("value", value) if isinstance(value, dict) else value
        group.external_id = external_id if external_id else None
    elif path == "urn:ietf:params:scim:schemas:neuroglancer:2.0:GroupPermissions:datasetPermissions":
        # Replace entire datasetPermissions array
        if isinstance(value, list):
            # Remove all existing permissions for this group
            GroupDatasetPermission.query.filter_by(group_id=group.id).delete()
            
            # Add all new permissions
            for dp in value:
                if isinstance(dp, dict):
                    dataset_scim_id = dp.get("datasetId")
                    permission_names = dp.get("permissions", [])
                    
                    dataset = find_dataset_by_scim_identifier(scim_id=dataset_scim_id)
                    if not dataset:
                        continue
                    
                    permission_ids = []
                    for perm_name in permission_names:
                        perm = Permission.query.filter_by(name=perm_name).first()
                        if perm:
                            permission_ids.append(perm.id)
                    
                    # Add permissions directly to session
                    for perm_id in permission_ids:
                        gd = GroupDatasetPermission(
                            group_id=group.id,
                            dataset_id=dataset.id,
                            permission_id=perm_id
                        )
                        db.session.add(gd)
    elif path.startswith(
        "urn:ietf:params:scim:schemas:neuroglancer:2.0:GroupPermissions:datasetPermissions"
    ) or path.endswith(":datasetPermissions"):
        # Replace dataset permissions (remove old, add new)
        if isinstance(value, dict):
            dataset_scim_id = value.get("datasetId")
            permission_names = value.get("permissions", [])
            
            # Find dataset
            dataset = find_dataset_by_scim_identifier(scim_id=dataset_scim_id)
            if not dataset:
                return
            
            # Remove all existing permissions for this dataset
            GroupDatasetPermission.query.filter_by(
                group_id=group.id,
                dataset_id=dataset.id
            ).delete()
            
            # Add new permissions
            permission_ids = []
            for perm_name in permission_names:
                perm = Permission.query.filter_by(name=perm_name).first()
                if perm:
                    permission_ids.append(perm.id)
            
            # Add permissions directly to session
            for perm_id in permission_ids:
                gd = GroupDatasetPermission(
                    group_id=group.id,
                    dataset_id=dataset.id,
                    permission_id=perm_id
                )
                db.session.add(gd)


def _handle_group_add(group, path, value, affected_users):
    """Handle add operation for Group."""
    from ..model.base import db
    
    if path.startswith("members[") or path == "members":
        # Add member to group
        members_to_add = []
        if path == "members":
            # Value is array of members
            if isinstance(value, list):
                for member_item in value:
                    member_scim_id = member_item.get("value") if isinstance(member_item, dict) else member_item
                    member_user = find_user_by_scim_identifier(scim_id=member_scim_id)
                    if member_user:
                        members_to_add.append(member_user)
        else:
            # Single member
            member_scim_id = value.get("value") if isinstance(value, dict) else value
            member_user = find_user_by_scim_identifier(scim_id=member_scim_id)
            if member_user:
                members_to_add.append(member_user)
        
        # Add all members (check for duplicates first)
        for member_user in members_to_add:
            existing_ug = UserGroup.get(group.id, member_user.id)
            if not existing_ug:
                ug = UserGroup(user_id=member_user.id, group_id=group.id)
                db.session.add(ug)
                affected_users.add(member_user.id)
    elif path == "urn:ietf:params:scim:schemas:neuroglancer:2.0:GroupPermissions:datasetPermissions":
        # Add entire datasetPermissions array
        if isinstance(value, list):
            for dp in value:
                if isinstance(dp, dict):
                    dataset_scim_id = dp.get("datasetId")
                    permission_names = dp.get("permissions", [])
                    
                    dataset = find_dataset_by_scim_identifier(scim_id=dataset_scim_id)
                    if not dataset:
                        continue
                    
                    permission_ids = []
                    for perm_name in permission_names:
                        perm = Permission.query.filter_by(name=perm_name).first()
                        if perm:
                            permission_ids.append(perm.id)
                    
                    # Add permissions directly to session (check for duplicates)
                    for perm_id in permission_ids:
                        existing = GroupDatasetPermission.query.filter_by(
                            group_id=group.id,
                            dataset_id=dataset.id,
                            permission_id=perm_id
                        ).first()
                        if not existing:
                            gd = GroupDatasetPermission(
                                group_id=group.id,
                                dataset_id=dataset.id,
                                permission_id=perm_id
                            )
                            db.session.add(gd)
    elif path.startswith(
        "urn:ietf:params:scim:schemas:neuroglancer:2.0:GroupPermissions:datasetPermissions"
    ) or path.endswith(":datasetPermissions"):
        # Add dataset permission
        if isinstance(value, dict):
            dataset_scim_id = value.get("datasetId")
            permission_names = value.get("permissions", [])
            
            # Find dataset
            dataset = find_dataset_by_scim_identifier(scim_id=dataset_scim_id)
            if not dataset:
                return
            
            # Map permission names to IDs
            permission_ids = []
            for perm_name in permission_names:
                perm = Permission.query.filter_by(name=perm_name).first()
                if perm:
                    permission_ids.append(perm.id)
            
            # Add permissions directly to session (check for duplicates)
            for perm_id in permission_ids:
                existing = GroupDatasetPermission.query.filter_by(
                    group_id=group.id,
                    dataset_id=dataset.id,
                    permission_id=perm_id
                ).first()
                if not existing:
                    gd = GroupDatasetPermission(
                        group_id=group.id,
                        dataset_id=dataset.id,
                        permission_id=perm_id
                    )
                    db.session.add(gd)


def _handle_group_remove(group, path, value, affected_users):
    """Handle remove operation for Group."""
    from ..model.base import db
    
    if path.startswith("members[") or path == "members":
        # Remove member from group
        members_to_remove = []
        if path == "members":
            # Value is array of members to remove
            if isinstance(value, list):
                for member_item in value:
                    member_scim_id = member_item.get("value") if isinstance(member_item, dict) else member_item
                    member_user = find_user_by_scim_identifier(scim_id=member_scim_id)
                    if member_user:
                        members_to_remove.append(member_user)
        elif value is None:
            # Remove all members from group
            # Get affected users before deletion
            affected_users_list = UserGroup.get_users(group.id)
            affected_users.update([u.id for u in affected_users_list])
            # Perform bulk delete
            UserGroup.query.filter_by(group_id=group.id).delete()
            return
        else:
            # Path contains filter expression like "members[value eq \"...\"]"
            # Extract identifier from path filter (RFC 7644: remove with filter has no value field)
            member_scim_id = extract_identifier_from_path_filter(path)
            if not member_scim_id:
                # Fallback: try to get from value if provided (for backward compatibility)
                member_scim_id = value.get("value") if isinstance(value, dict) else value
            
            if member_scim_id:
                member_user = find_user_by_scim_identifier(scim_id=member_scim_id)
                if member_user:
                    members_to_remove.append(member_user)
        
        # Remove all members
        for member_user in members_to_remove:
            ug = UserGroup.get(group.id, member_user.id)
            if ug:
                db.session.delete(ug)
                affected_users.add(member_user.id)
    elif path.startswith(
        "urn:ietf:params:scim:schemas:neuroglancer:2.0:GroupPermissions:datasetPermissions"
    ) or path.endswith(":datasetPermissions"):
        # Remove dataset permission
        if isinstance(value, dict):
            dataset_scim_id = value.get("datasetId")
            permission_names = value.get("permissions", [])
            
            # Find dataset
            dataset = find_dataset_by_scim_identifier(scim_id=dataset_scim_id)
            if not dataset:
                return
            
            # Remove each permission
            for perm_name in permission_names:
                perm = Permission.query.filter_by(name=perm_name).first()
                if perm:
                    GroupDatasetPermission.query.filter_by(
                        group_id=group.id,
                        dataset_id=dataset.id,
                        permission_id=perm.id
                    ).delete()


@scim_bp.route("/Groups/<scim_id>", methods=["PATCH"])
@scim_auth_required
def patch_group(scim_id):
    """Partial update Group."""
    from ..model.base import db
    
    # Find group by scim_id
    group = find_group_by_scim_identifier(scim_id=scim_id)
    
    if not group:
        return build_error_response(404, "NOT_FOUND", f"Group {scim_id} not found")
    
    data = flask.request.get_json()
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Track affected users for cache updates (after commit)
    affected_users = set()
    
    # Handle PATCH operations atomically - all succeed or all fail
    operations = data.get("Operations", [])
    
    try:
        for op in operations:
            op_type = op.get("op")
            path = op.get("path", "")
            value = op.get("value")
            
            if op_type == "replace":
                _handle_group_replace(group, path, value)
            elif op_type == "add":
                _handle_group_add(group, path, value, affected_users)
            elif op_type == "remove":
                _handle_group_remove(group, path, value, affected_users)
        
        # Commit all changes atomically
        db.session.commit()
        
        # Update caches after all changes are committed
        for user_id in affected_users:
            user = User.get_by_id(user_id)
            if user:
                user.update_cache()
        group.update_cache()
        
    except sqlalchemy.exc.IntegrityError as e:
        # Database integrity error
        db.session.rollback()
        error_msg = str(e.orig) if hasattr(e, 'orig') else str(e)
        if "unique" in error_msg.lower() or "duplicate" in error_msg.lower():
            return build_error_response(409, "uniqueness", "A constraint violation occurred.")
        return build_error_response(400, "invalidValue", f"Database constraint violation: {error_msg}")
    except Exception as e:
        # Any other error - rollback and return error
        db.session.rollback()
        return build_error_response(400, "invalidValue", str(e))
    
    # Serialize and return
    resource = GroupSCIMSerializer.to_scim(group)
    response = flask.jsonify(resource)
    response.headers["Content-Type"] = "application/scim+json"
    return response


@scim_bp.route("/Groups/<scim_id>", methods=["DELETE"])
@scim_auth_required
def delete_group(scim_id):
    """Delete Group."""
    # Find group by scim_id
    group = find_group_by_scim_identifier(scim_id=scim_id)
    
    if not group:
        return build_error_response(404, "NOT_FOUND", f"Group {scim_id} not found")
    
    # Delete group (remove all memberships and permissions first)
    from ..model.user_group import UserGroup
    from ..model.group_dataset_permission import GroupDatasetPermission
    from ..model.base import db
    from ..model.user import User
    
    # Get all affected user IDs BEFORE deleting memberships
    # This is critical: we need the user list before bulk delete, since
    # group.update_cache() queries UserGroup.get_users() which would return
    # nothing after deletion. Individual UserGroup.delete() calls update_cache(),
    # but bulk query.delete() bypasses that.
    affected_users = UserGroup.get_users(group.id)
    affected_user_ids = [user.id for user in affected_users]
    
    # Remove all UserGroup memberships
    UserGroup.query.filter_by(group_id=group.id).delete()
    
    # Remove all GroupDatasetPermission records
    GroupDatasetPermission.query.filter_by(group_id=group.id).delete()
    
    # Now safe to delete the group
    db.session.delete(group)
    db.session.commit()
    
    # Update cache for all affected users (they lost group membership and permissions)
    for user_id in affected_user_ids:
        user = User.get_by_id(user_id)
        if user:
            user.update_cache()
    
    return flask.Response(status=204)


# ============================================================================
# Dataset Endpoints (Custom Resource Type)
# ============================================================================


@scim_bp.route("/Datasets", methods=["GET"])
@scim_auth_required
def list_datasets():
    """List/search Datasets."""
    # Parse pagination
    try:
        start_index, count = parse_pagination_params()
    except SCIMPaginationError as e:
        return build_error_response(
            400,
            "invalidValue",
            str(e)
        )
    
    # Parse filter
    filter_expr = flask.request.args.get("filter")
    
    # Build query
    query = Dataset.query
    
    # Apply filter
    if filter_expr:
        try:
            query = SCIMFilterParser.apply_dataset_filter(query, filter_expr)
        except SCIMFilterError as e:
            return build_error_response(
                400,
                "invalidFilter",
                f"Invalid filter expression: {str(e)}"
            )
    
    # Get total count
    total_results = query.count()
    
    # Apply pagination
    offset = start_index - 1
    datasets = query.offset(offset).limit(count).all()
    
    # Serialize
    resources = [DatasetSCIMSerializer.to_scim(dataset) for dataset in datasets]
    
    # Build response
    response_data = build_list_response(resources, total_results, start_index, len(resources))
    response = flask.jsonify(response_data)
    response.headers["Content-Type"] = "application/scim+json"
    return response


@scim_bp.route("/Datasets/<scim_id>", methods=["GET"])
@scim_auth_required
def get_dataset(scim_id):
    """Get specific Dataset by SCIM ID."""
    # Find dataset by scim_id
    dataset = find_dataset_by_scim_identifier(scim_id=scim_id)
    
    if dataset:
        resource = DatasetSCIMSerializer.to_scim(dataset)
        response = flask.jsonify(resource)
        response.headers["Content-Type"] = "application/scim+json"
        return response
    
    return build_error_response(404, "NOT_FOUND", f"Dataset {scim_id} not found")


@scim_bp.route("/Datasets", methods=["POST"])
@scim_auth_required
def create_dataset():
    """Create new Dataset."""
    data = flask.request.get_json()
    
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Convert SCIM to internal format
    dataset_data = DatasetSCIMSerializer.from_scim(data)
    
    # Validate required fields
    if "name" not in dataset_data:
        return build_error_response(400, "invalidValue", "name required")
    
    # SCIM 2.0 RFC 7644: POST is NOT idempotent - always return 409 Conflict if resource exists
    # Check for existing dataset by externalId (if provided) or name
    existing_dataset = None
    
    # Check by externalId first (if provided)
    if "external_id" in dataset_data and dataset_data["external_id"]:
        existing_dataset = Dataset.query.filter_by(external_id=dataset_data["external_id"]).first()
        if existing_dataset:
            return build_error_response(
                409,
                "uniqueness",
                f"Dataset with externalId '{dataset_data['external_id']}' already exists.",
            )
    
    # Check by name
    existing_dataset = Dataset.query.filter_by(name=dataset_data["name"]).first()
    if existing_dataset:
        return build_error_response(
            409,
            "uniqueness",
            f"Dataset with name '{dataset_data['name']}' already exists. "
            "Search for the dataset first, then use PATCH to update externalId to link it.",
        )
    
    # Dataset doesn't exist, create new one
    try:
        dataset = create_dataset_with_scim(
            name=dataset_data["name"],
            tos_id=dataset_data.get("tos_id"),
            external_id=dataset_data.get("external_id"),
        )
        
        # Handle ServiceTable mappings if provided
        service_tables = data.get("serviceTables", [])
        for st in service_tables:
            ServiceTable.add(
                service_name=st["serviceName"],
                table_name=st["tableName"],
                dataset=dataset.name,
            )
        
        # Serialize and return
        resource = DatasetSCIMSerializer.to_scim(dataset)
        response = flask.jsonify(resource)
        response.status_code = 201
        response.headers["Content-Type"] = "application/scim+json"
        response.headers["Location"] = resource["meta"]["location"]
        return response
        
    except sqlalchemy.exc.IntegrityError:
        # Race condition: dataset was created between our check and creation
        # Return 409 Conflict per SCIM spec (POST is not idempotent)
        from ..model.base import db
        db.session.rollback()  # Rollback invalid session state before querying
        existing_dataset = Dataset.query.filter_by(name=dataset_data["name"]).first()
        if existing_dataset:
            return build_error_response(
                409,
                "uniqueness",
                f"Dataset with name '{dataset_data['name']}' already exists.",
            )
        # If still not found, return generic conflict error
        return build_error_response(409, "uniqueness", "Dataset already exists")
    except ValueError as e:
        return build_error_response(400, "invalidValue", str(e))


@scim_bp.route("/Datasets/<scim_id>", methods=["PUT"])
@scim_auth_required
def replace_dataset(scim_id):
    """Replace Dataset (full update)."""
    # Find dataset by scim_id
    dataset = find_dataset_by_scim_identifier(scim_id=scim_id)
    
    if not dataset:
        return build_error_response(404, "NOT_FOUND", f"Dataset {scim_id} not found")
    
    data = flask.request.get_json()
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Convert SCIM to internal format
    dataset_data = DatasetSCIMSerializer.from_scim(data)
    
    from ..model.base import db
    
    try:
        # Update external_id directly (Dataset.update() only processes name and tos_id)
        if "external_id" in dataset_data:
            dataset.external_id = dataset_data["external_id"]
        
        # Update dataset fields manually to avoid premature commit
        # (dataset.update() commits internally, which breaks atomicity)
        fields = ["name", "tos_id"]
        for field in fields:
            if field in dataset_data:
                setattr(dataset, field, dataset_data[field])
        
        # Update ServiceTable mappings if provided
        if "serviceTables" in data:
            # Remove existing mappings (don't commit yet)
            ServiceTable.query.filter_by(dataset_id=dataset.id).delete()
            
            # Add new mappings (don't commit yet - ServiceTable.add() commits internally)
            # Manually create ServiceTable records instead of using ServiceTable.add()
            # to avoid premature commits and ensure atomicity
            for st in data["serviceTables"]:
                service_table = ServiceTable(
                    service_name=st["serviceName"],
                    table_name=st["tableName"],
                    dataset_id=dataset.id,
                )
                db.session.add(service_table)
        
        # Commit all changes atomically
        db.session.commit()
        
        # Update cache after successful commit
        dataset.update_cache()
        
    except Exception as e:
        # Rollback all changes if any operation fails
        # This ensures transaction atomicity - either all updates succeed or none do
        db.session.rollback()
        return build_error_response(400, "invalidValue", str(e))
    
    # Serialize and return
    resource = DatasetSCIMSerializer.to_scim(dataset)
    response = flask.jsonify(resource)
    response.headers["Content-Type"] = "application/scim+json"
    return response


# Helper functions for Dataset PATCH operations
def _handle_dataset_replace(dataset, path, value):
    """Handle replace operation for Dataset."""
    from ..model.base import db
    
    if path == "name":
        # Update name directly (avoid dataset.update() which commits internally)
        dataset.name = value
    elif path == "tosId":
        # Update tos_id directly (avoid dataset.update() which commits internally)
        dataset.tos_id = value
    elif path == "externalId":
        # Update external_id
        external_id = value.get("value", value) if isinstance(value, dict) else value
        dataset.external_id = external_id if external_id else None
    elif path.startswith("serviceTables[") and "]" in path:
        # Replace specific service table entry
        # Path format: "serviceTables[value eq \"service:table\"]" or "serviceTables[0]"
        if isinstance(value, dict):
            service_name = value.get("serviceName")
            table_name = value.get("tableName")
            
            # Try to parse index from path like "serviceTables[0]"
            index_match = re.search(r'serviceTables\[(\d+)\]', path)
            if index_match:
                # Remove the specific entry by index (don't commit yet)
                service_tables = ServiceTable.query.filter_by(dataset_id=dataset.id).all()
                idx = int(index_match.group(1))
                if 0 <= idx < len(service_tables):
                    st = service_tables[idx]
                    ServiceTable.query.filter_by(
                        service_name=st.service_name,
                        table_name=st.table_name,
                        dataset_id=dataset.id
                    ).delete()
            
            # Add new entry (don't commit yet - create manually to avoid ServiceTable.add() commit)
            if service_name and table_name:
                # Check if already exists
                existing = ServiceTable.query.filter_by(
                    service_name=service_name,
                    table_name=table_name,
                    dataset_id=dataset.id
                ).first()
                if not existing:
                    service_table = ServiceTable(
                        service_name=service_name,
                        table_name=table_name,
                        dataset_id=dataset.id,
                    )
                    db.session.add(service_table)
    elif path == "serviceTables":
        # Replace entire serviceTables array
        if isinstance(value, list):
            # Remove all existing service tables (don't commit yet)
            ServiceTable.query.filter_by(dataset_id=dataset.id).delete()
            
            # Add new service tables (don't commit yet - create manually to avoid ServiceTable.add() commit)
            for st in value:
                if isinstance(st, dict):
                    service_name = st.get("serviceName")
                    table_name = st.get("tableName")
                    if service_name and table_name:
                        # Check if already exists (shouldn't after delete, but be safe)
                        existing = ServiceTable.query.filter_by(
                            service_name=service_name,
                            table_name=table_name,
                            dataset_id=dataset.id
                        ).first()
                        if not existing:
                            service_table = ServiceTable(
                                service_name=service_name,
                                table_name=table_name,
                                dataset_id=dataset.id,
                            )
                            db.session.add(service_table)


def _handle_dataset_add(dataset, path, value):
    """Handle add operation for Dataset."""
    from ..model.base import db
    
    if path.startswith("serviceTables[") or path == "serviceTables":
        # Add service table mapping
        if path == "serviceTables":
            # Value is array
            if isinstance(value, list):
                for st in value:
                    if isinstance(st, dict):
                        service_name = st.get("serviceName")
                        table_name = st.get("tableName")
                        if service_name and table_name:
                            # Check if already exists
                            existing = ServiceTable.query.filter_by(
                                service_name=service_name,
                                table_name=table_name,
                                dataset_id=dataset.id
                            ).first()
                            if not existing:
                                service_table = ServiceTable(
                                    service_name=service_name,
                                    table_name=table_name,
                                    dataset_id=dataset.id,
                                )
                                db.session.add(service_table)
        else:
            # Single service table
            if isinstance(value, dict):
                service_name = value.get("serviceName")
                table_name = value.get("tableName")
                if service_name and table_name:
                    # Check if already exists
                    existing = ServiceTable.query.filter_by(
                        service_name=service_name,
                        table_name=table_name,
                        dataset_id=dataset.id
                    ).first()
                    if not existing:
                        service_table = ServiceTable(
                            service_name=service_name,
                            table_name=table_name,
                            dataset_id=dataset.id,
                        )
                        db.session.add(service_table)


def _handle_dataset_remove(dataset, path, value):
    """Handle remove operation for Dataset."""
    from ..model.base import db
    
    if path.startswith("serviceTables[") or path == "serviceTables":
        # Remove service table mapping
        if path == "serviceTables":
            # Value is array of service tables to remove
            if isinstance(value, list):
                for st in value:
                    if isinstance(st, dict):
                        service_name = st.get("serviceName")
                        table_name = st.get("tableName")
                        if service_name and table_name:
                            # Remove directly (don't commit yet - avoid ServiceTable.remove() commit)
                            ServiceTable.query.filter_by(
                                service_name=service_name,
                                table_name=table_name,
                                dataset_id=dataset.id
                            ).delete()
        else:
            # Single service table to remove
            # Try to parse index or value
            index_match = re.search(r'serviceTables\[(\d+)\]', path)
            if index_match:
                # Remove by index
                service_tables = ServiceTable.query.filter_by(dataset_id=dataset.id).all()
                idx = int(index_match.group(1))
                if 0 <= idx < len(service_tables):
                    st = service_tables[idx]
                    # Remove directly (don't commit yet - avoid ServiceTable.remove() commit)
                    ServiceTable.query.filter_by(
                        service_name=st.service_name,
                        table_name=st.table_name,
                        dataset_id=dataset.id
                    ).delete()
            elif isinstance(value, dict):
                # Remove by serviceName and tableName
                service_name = value.get("serviceName")
                table_name = value.get("tableName")
                if service_name and table_name:
                    # Remove directly (don't commit yet - avoid ServiceTable.remove() commit)
                    ServiceTable.query.filter_by(
                        service_name=service_name,
                        table_name=table_name,
                        dataset_id=dataset.id
                    ).delete()


@scim_bp.route("/Datasets/<scim_id>", methods=["PATCH"])
@scim_auth_required
def patch_dataset(scim_id):
    """Partial update Dataset."""
    from ..model.base import db
    
    # Find dataset by scim_id
    dataset = find_dataset_by_scim_identifier(scim_id=scim_id)
    
    if not dataset:
        return build_error_response(404, "NOT_FOUND", f"Dataset {scim_id} not found")
    
    data = flask.request.get_json()
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Handle PATCH operations atomically - all succeed or all fail
    operations = data.get("Operations", [])
    
    try:
        for op in operations:
            op_type = op.get("op")
            path = op.get("path", "")
            value = op.get("value")
            
            if op_type == "replace":
                _handle_dataset_replace(dataset, path, value)
            elif op_type == "add":
                _handle_dataset_add(dataset, path, value)
            elif op_type == "remove":
                _handle_dataset_remove(dataset, path, value)
        
        # Commit all changes atomically
        db.session.commit()
        
        # Update cache after all changes are committed
        dataset.update_cache()
        
    except sqlalchemy.exc.IntegrityError as e:
        # Database integrity error
        db.session.rollback()
        error_msg = str(e.orig) if hasattr(e, 'orig') else str(e)
        if "unique" in error_msg.lower() or "duplicate" in error_msg.lower():
            return build_error_response(409, "uniqueness", "A constraint violation occurred.")
        return build_error_response(400, "invalidValue", f"Database constraint violation: {error_msg}")
    except Exception as e:
        # Any other error - rollback and return error
        db.session.rollback()
        return build_error_response(400, "invalidValue", str(e))
    
    # Serialize and return
    resource = DatasetSCIMSerializer.to_scim(dataset)
    response = flask.jsonify(resource)
    response.headers["Content-Type"] = "application/scim+json"
    return response


@scim_bp.route("/Datasets/<scim_id>", methods=["DELETE"])
@scim_auth_required
def delete_dataset(scim_id):
    """Delete Dataset."""
    # Find dataset by scim_id
    dataset = find_dataset_by_scim_identifier(scim_id=scim_id)
    
    if not dataset:
        return build_error_response(404, "NOT_FOUND", f"Dataset {scim_id} not found")
    
    from ..model.base import db
    
    # Delete all related records before deleting the dataset
    # 1. Delete ServiceTable mappings
    ServiceTable.query.filter_by(dataset_id=dataset.id).delete()
    
    # 2. Delete GroupDatasetPermission records and update affected group caches
    affected_groups = (
        db.session.query(GroupDatasetPermission.group_id)
        .filter_by(dataset_id=dataset.id)
        .distinct()
        .all()
    )
    GroupDatasetPermission.query.filter_by(dataset_id=dataset.id).delete()
    # Update cache for affected groups
    for (group_id,) in affected_groups:
        group = Group.get_by_id(group_id)
        if group:
            group.update_cache()
    
    # 3. Delete DatasetAdmin records
    DatasetAdmin.query.filter_by(dataset_id=dataset.id).delete()
    
    # 4. Delete the dataset
    db.session.delete(dataset)
    db.session.commit()
    
    return flask.Response(status=204)
