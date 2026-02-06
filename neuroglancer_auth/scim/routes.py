"""
SCIM 2.0 API routes.

Implements SCIM 2.0 endpoints for Users, Groups, and Datasets (custom resource type).
"""

import re
import os
import flask
import sqlalchemy
from ..model.dataset import Dataset
from ..model.group import Group
from ..model.group_dataset_permission import GroupDatasetPermission
from ..model.permission import Permission
from ..model.table_mapping import ServiceTable
from ..model.user import User
from ..model.user_group import UserGroup
from .auth import scim_auth_required
from .filter import SCIMFilterParser
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
)

URL_PREFIX = os.environ.get("URL_PREFIX", "auth")

# Create SCIM blueprint
scim_bp = flask.Blueprint("scim_bp", __name__, url_prefix="/" + URL_PREFIX + "/scim/v2")

# ============================================================================
# Discovery Endpoints
# ============================================================================


@scim_bp.route("/ServiceProviderConfig", methods=["GET"])
@scim_auth_required
def service_provider_config():
    """SCIM Service Provider Configuration endpoint."""
    base_url = get_base_url()
    
    return flask.jsonify(
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
    
    return flask.jsonify(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(resource_types),
            "Resources": resource_types,
        }
    )


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
    
    return flask.jsonify(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(schemas_list),
            "Resources": schemas_list,
        }
    )


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
    start_index, count = parse_pagination_params()
    
    # Parse filter
    filter_expr = flask.request.args.get("filter")
    
    # Build query
    query = User.query.filter(User.parent_id.is_(None))  # Exclude service accounts
    
    # Apply filter
    if filter_expr:
        query = SCIMFilterParser.apply_user_filter(query, filter_expr)
    
    # Get total count
    total_results = query.count()
    
    # Apply pagination (SCIM uses 1-based indexing)
    offset = start_index - 1
    users = query.offset(offset).limit(count).all()
    
    # Serialize
    resources = [UserSCIMSerializer.to_scim(user) for user in users]
    
    # Build response
    response = build_list_response(resources, total_results, start_index, len(resources))
    return flask.jsonify(response)


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
    
    # Update external_id if provided
    if "external_id" in user_data:
        user.external_id = user_data["external_id"]
        from ..model.base import db
        db.session.commit()
    
    # Update user (remove external_id from update_data as it's already handled)
    # Also sanitize pi field to prevent IntegrityError if it's None
    update_data = {k: v for k, v in user_data.items() if k != "external_id"}
    if "pi" in update_data:
        update_data["pi"] = _sanitize_pi_field(update_data["pi"])
    try:
        if update_data:
            user.update(update_data)
        
        # Serialize and return
        resource = UserSCIMSerializer.to_scim(user)
        response = flask.jsonify(resource)
        response.headers["Content-Type"] = "application/scim+json"
        return response
        
    except Exception as e:
        return build_error_response(400, "invalidValue", str(e))


@scim_bp.route("/Users/<scim_id>", methods=["PATCH"])
@scim_auth_required
def patch_user(scim_id):
    """Partial update User."""
    # Find user by scim_id
    user = find_user_by_scim_identifier(scim_id=scim_id)
    
    if not user:
        return build_error_response(404, "NOT_FOUND", f"User {scim_id} not found")
    
    data = flask.request.get_json()
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Handle PATCH operations
    operations = data.get("Operations", [])
    
    for op in operations:
        op_type = op.get("op")
        path = op.get("path", "")
        value = op.get("value")
        
        if op_type == "replace":
            # Handle path-based updates
            if path == "userName" or path.startswith("emails["):
                if isinstance(value, dict):
                    user.update({"email": value.get("value", value)})
                else:
                    user.update({"email": value})
            elif path == "name.givenName" or path == "name.familyName" or path == "displayName":
                # Update name
                if isinstance(value, dict):
                    name = f"{value.get('givenName', '')} {value.get('familyName', '')}".strip()
                else:
                    name = value
                user.update({"name": name})
            elif isinstance(value, dict):
                # Direct value update
                user_data = UserSCIMSerializer.from_scim({"schemas": [], **value})
                # Sanitize pi field to prevent IntegrityError if it's None
                if "pi" in user_data:
                    user_data["pi"] = _sanitize_pi_field(user_data["pi"])
                user.update(user_data)
        
        elif op_type == "add":
            # Add operation
            if path.startswith("groups[") or path == "groups":
                # Add user to group
                if path == "groups":
                    # Value is array of groups
                    if isinstance(value, list):
                        for group_item in value:
                            group_scim_id = group_item.get("value") if isinstance(group_item, dict) else group_item
                            group = find_group_by_scim_identifier(scim_id=group_scim_id)
                            if group:
                                try:
                                    UserGroup.add(user.id, group.id)
                                    user.update_cache()  # Update user cache after group change
                                except sqlalchemy.exc.IntegrityError:
                                    pass  # Already in group
                else:
                    # Single group in path like "groups[value eq \"...\"]" or direct value
                    group_scim_id = value.get("value") if isinstance(value, dict) else value
                    group = find_group_by_scim_identifier(scim_id=group_scim_id)
                    if group:
                        try:
                            UserGroup.add(user.id, group.id)
                            user.update_cache()  # Update user cache after group change
                        except sqlalchemy.exc.IntegrityError:
                            pass  # Already in group
        
        elif op_type == "remove":
            # Remove operation
            if path.startswith("groups[") or path == "groups":
                # Remove user from group
                if path == "groups":
                    # Value is array of groups to remove
                    if isinstance(value, list):
                        for group_item in value:
                            group_scim_id = group_item.get("value") if isinstance(group_item, dict) else group_item
                            group = find_group_by_scim_identifier(scim_id=group_scim_id)
                            if group:
                                ug = UserGroup.get(group.id, user.id)
                                if ug:
                                    ug.delete()
                                    user.update_cache()  # Update user cache after group change
                else:
                    # Single group to remove
                    group_scim_id = value.get("value") if isinstance(value, dict) else value
                    group = find_group_by_scim_identifier(scim_id=group_scim_id)
                    if group:
                        ug = UserGroup.get(group.id, user.id)
                        if ug:
                            ug.delete()
                            user.update_cache()  # Update user cache after group change
    
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
    start_index, count = parse_pagination_params()
    
    # Parse filter
    filter_expr = flask.request.args.get("filter")
    
    # Build query
    query = Group.query
    
    # Apply filter
    if filter_expr:
        query = SCIMFilterParser.apply_group_filter(query, filter_expr)
    
    # Get total count
    total_results = query.count()
    
    # Apply pagination
    offset = start_index - 1
    groups = query.offset(offset).limit(count).all()
    
    # Serialize
    resources = [GroupSCIMSerializer.to_scim(group) for group in groups]
    
    # Build response
    response = build_list_response(resources, total_results, start_index, len(resources))
    return flask.jsonify(response)


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
    # Find group by scim_id
    group = find_group_by_scim_identifier(scim_id=scim_id)
    
    if not group:
        return build_error_response(404, "NOT_FOUND", f"Group {scim_id} not found")
    
    data = flask.request.get_json()
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Convert SCIM to internal format
    group_data = GroupSCIMSerializer.from_scim(data)
    
    # Update group (Group model doesn't have update method, so update directly)
    if "name" in group_data:
        group.name = group_data["name"]
    if "external_id" in group_data:
        group.external_id = group_data["external_id"]
    
    from ..model.base import db
    db.session.commit()
    group.update_cache()  # Update user caches
    
    # Serialize and return
    resource = GroupSCIMSerializer.to_scim(group)
    response = flask.jsonify(resource)
    response.headers["Content-Type"] = "application/scim+json"
    return response


@scim_bp.route("/Groups/<scim_id>", methods=["PATCH"])
@scim_auth_required
def patch_group(scim_id):
    """Partial update Group."""
    # Find group by scim_id
    group = find_group_by_scim_identifier(scim_id=scim_id)
    
    if not group:
        return build_error_response(404, "NOT_FOUND", f"Group {scim_id} not found")
    
    data = flask.request.get_json()
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Handle PATCH operations
    operations = data.get("Operations", [])
    
    for op in operations:
        op_type = op.get("op")
        path = op.get("path", "")
        value = op.get("value")
        
        if op_type == "replace":
            if path == "displayName":
                group.name = value
                from ..model.base import db
                db.session.commit()
                group.update_cache()
            elif path == "urn:ietf:params:scim:schemas:neuroglancer:2.0:GroupPermissions:datasetPermissions":
                # Replace entire datasetPermissions array
                if isinstance(value, list):
                    # Remove all existing permissions for this group
                    GroupDatasetPermission.query.filter_by(group_id=group.id).delete()
                    from ..model.base import db
                    db.session.commit()
                    
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
                            
                            if permission_ids:
                                GroupDatasetPermission.add(
                                    group_id=group.id,
                                    dataset_id=dataset.id,
                                    permission_ids=permission_ids
                                )
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
                        continue
                    
                    # Remove all existing permissions for this dataset
                    GroupDatasetPermission.query.filter_by(
                        group_id=group.id,
                        dataset_id=dataset.id
                    ).delete()
                    from ..model.base import db
                    db.session.commit()
                    
                    # Add new permissions
                    permission_ids = []
                    for perm_name in permission_names:
                        perm = Permission.query.filter_by(name=perm_name).first()
                        if perm:
                            permission_ids.append(perm.id)
                    
                    if permission_ids:
                        GroupDatasetPermission.add(
                            group_id=group.id,
                            dataset_id=dataset.id,
                            permission_ids=permission_ids
                        )
        
        elif op_type == "add":
            if path.startswith("members[") or path == "members":
                # Add member to group
                if path == "members":
                    # Value is array of members
                    if isinstance(value, list):
                        for member_item in value:
                            member_scim_id = member_item.get("value") if isinstance(member_item, dict) else member_item
                            member_user = find_user_by_scim_identifier(scim_id=member_scim_id)
                            if member_user:
                                try:
                                    UserGroup.add(member_user.id, group.id)
                                    member_user.update_cache()  # Update member cache
                                    group.update_cache()  # Update group cache
                                except sqlalchemy.exc.IntegrityError:
                                    pass  # Already in group
                else:
                    # Single member
                    member_scim_id = value.get("value") if isinstance(value, dict) else value
                    member_user = find_user_by_scim_identifier(scim_id=member_scim_id)
                    if member_user:
                        try:
                            UserGroup.add(member_user.id, group.id)
                            member_user.update_cache()  # Update member cache
                            group.update_cache()  # Update group cache
                        except sqlalchemy.exc.IntegrityError:
                            pass  # Already in group
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
                            
                            if permission_ids:
                                try:
                                    GroupDatasetPermission.add(
                                        group_id=group.id,
                                        dataset_id=dataset.id,
                                        permission_ids=permission_ids
                                    )
                                except sqlalchemy.exc.IntegrityError:
                                    pass
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
        
        elif op_type == "remove":
            if path.startswith("members[") or path == "members":
                # Remove member from group
                if path == "members":
                    # Value is array of members to remove
                    if isinstance(value, list):
                        for member_item in value:
                            member_scim_id = member_item.get("value") if isinstance(member_item, dict) else member_item
                            member_user = find_user_by_scim_identifier(scim_id=member_scim_id)
                            if member_user:
                                ug = UserGroup.get(group.id, member_user.id)
                                if ug:
                                    ug.delete()
                                    member_user.update_cache()  # Update member cache
                                    group.update_cache()  # Update group cache
                else:
                    # Single member to remove
                    member_scim_id = value.get("value") if isinstance(value, dict) else value
                    member_user = find_user_by_scim_identifier(scim_id=member_scim_id)
                    if member_user:
                        ug = UserGroup.get(group.id, member_user.id)
                        if ug:
                            ug.delete()
                            member_user.update_cache()  # Update member cache
                            group.update_cache()  # Update group cache
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
                        continue
                    
                    # Remove each permission
                    for perm_name in permission_names:
                        perm = Permission.query.filter_by(name=perm_name).first()
                        if perm:
                            try:
                                GroupDatasetPermission.remove(
                                    group_id=group.id,
                                    dataset_id=dataset.id,
                                    permission_id=perm.id
                                )
                            except Exception:
                                pass  # Permission doesn't exist
    
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
    
    # Remove all UserGroup memberships
    UserGroup.query.filter_by(group_id=group.id).delete()
    
    # Remove all GroupDatasetPermission records
    GroupDatasetPermission.query.filter_by(group_id=group.id).delete()
    
    # Now safe to delete the group
    db.session.delete(group)
    db.session.commit()
    
    return flask.Response(status=204)


# ============================================================================
# Dataset Endpoints (Custom Resource Type)
# ============================================================================


@scim_bp.route("/Datasets", methods=["GET"])
@scim_auth_required
def list_datasets():
    """List/search Datasets."""
    # Parse pagination
    start_index, count = parse_pagination_params()
    
    # Parse filter
    filter_expr = flask.request.args.get("filter")
    
    # Build query
    query = Dataset.query
    
    # Apply filter
    if filter_expr:
        query = SCIMFilterParser.apply_dataset_filter(query, filter_expr)
    
    # Get total count
    total_results = query.count()
    
    # Apply pagination
    offset = start_index - 1
    datasets = query.offset(offset).limit(count).all()
    
    # Serialize
    resources = [DatasetSCIMSerializer.to_scim(dataset) for dataset in datasets]
    
    # Build response
    response = build_list_response(resources, total_results, start_index, len(resources))
    return flask.jsonify(response)


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
    
    # Update dataset using existing method
    dataset.update(dataset_data)
    
    # Update ServiceTable mappings if provided
    if "serviceTables" in data:
        # Remove existing mappings
        ServiceTable.query.filter_by(dataset_id=dataset.id).delete()
        from ..model.base import db
        
        db.session.commit()
        
        # Add new mappings
        for st in data["serviceTables"]:
            ServiceTable.add(
                service_name=st["serviceName"],
                table_name=st["tableName"],
                dataset=dataset.name,
            )
    
    # Serialize and return
    resource = DatasetSCIMSerializer.to_scim(dataset)
    response = flask.jsonify(resource)
    response.headers["Content-Type"] = "application/scim+json"
    return response


@scim_bp.route("/Datasets/<scim_id>", methods=["PATCH"])
@scim_auth_required
def patch_dataset(scim_id):
    """Partial update Dataset."""
    # Find dataset by scim_id
    dataset = find_dataset_by_scim_identifier(scim_id=scim_id)
    
    if not dataset:
        return build_error_response(404, "NOT_FOUND", f"Dataset {scim_id} not found")
    
    data = flask.request.get_json()
    if not data:
        return build_error_response(400, "invalidSyntax", "Request body required")
    
    # Handle PATCH operations
    operations = data.get("Operations", [])
    
    for op in operations:
        op_type = op.get("op")
        path = op.get("path", "")
        value = op.get("value")
        
        if op_type == "replace":
            if path == "name":
                dataset.update({"name": value})
            elif path == "tosId":
                dataset.update({"tos_id": value})
            elif path.startswith("serviceTables[") and "]" in path:
                # Replace specific service table entry
                # Path format: "serviceTables[value eq \"service:table\"]" or "serviceTables[0]"
                if isinstance(value, dict):
                    service_name = value.get("serviceName")
                    table_name = value.get("tableName")
                    
                    # Try to parse index from path like "serviceTables[0]"
                    index_match = re.search(r'serviceTables\[(\d+)\]', path)
                    if index_match:
                        # Remove the specific entry by index
                        service_tables = ServiceTable.query.filter_by(dataset_id=dataset.id).all()
                        idx = int(index_match.group(1))
                        if 0 <= idx < len(service_tables):
                            st = service_tables[idx]
                            ServiceTable.remove(st.service_name, st.table_name, dataset.name)
                    
                    # Add new entry
                    if service_name and table_name:
                        try:
                            ServiceTable.add(
                                service_name=service_name,
                                table_name=table_name,
                                dataset=dataset.name,
                            )
                        except sqlalchemy.exc.IntegrityError:
                            pass  # Already exists
            elif path == "serviceTables":
                # Replace entire serviceTables array
                if isinstance(value, list):
                    # Remove all existing service tables
                    ServiceTable.query.filter_by(dataset_id=dataset.id).delete()
                    from ..model.base import db
                    db.session.commit()
                    
                    # Add new service tables
                    for st in value:
                        if isinstance(st, dict):
                            try:
                                ServiceTable.add(
                                    service_name=st["serviceName"],
                                    table_name=st["tableName"],
                                    dataset=dataset.name,
                                )
                            except sqlalchemy.exc.IntegrityError:
                                pass
        
        elif op_type == "add":
            if path.startswith("serviceTables[") or path == "serviceTables":
                # Add service table mapping
                if path == "serviceTables":
                    # Value is array
                    if isinstance(value, list):
                        for st in value:
                            if isinstance(st, dict):
                                try:
                                    ServiceTable.add(
                                        service_name=st["serviceName"],
                                        table_name=st["tableName"],
                                        dataset=dataset.name,
                                    )
                                except sqlalchemy.exc.IntegrityError:
                                    pass  # Already exists
                else:
                    # Single service table
                    if isinstance(value, dict):
                        try:
                            ServiceTable.add(
                                service_name=value["serviceName"],
                                table_name=value["tableName"],
                                dataset=dataset.name,
                            )
                        except sqlalchemy.exc.IntegrityError:
                            pass  # Already exists
        
        elif op_type == "remove":
            if path.startswith("serviceTables[") or path == "serviceTables":
                # Remove service table mapping
                if path == "serviceTables":
                    # Value is array of service tables to remove
                    if isinstance(value, list):
                        for st in value:
                            if isinstance(st, dict):
                                try:
                                    ServiceTable.remove(
                                        service_name=st["serviceName"],
                                        table_name=st["tableName"],
                                        dataset=dataset.name,
                                    )
                                except ValueError:
                                    pass  # Doesn't exist
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
                            try:
                                ServiceTable.remove(st.service_name, st.table_name, dataset.name)
                            except ValueError:
                                pass
                    elif isinstance(value, dict):
                        # Remove by serviceName and tableName
                        try:
                            ServiceTable.remove(
                                service_name=value.get("serviceName"),
                                table_name=value.get("tableName"),
                                dataset=dataset.name,
                            )
                        except ValueError:
                            pass
    
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
    
    # Delete dataset (remove ServiceTable mappings first)
    ServiceTable.query.filter_by(dataset_id=dataset.id).delete()
    from ..model.base import db
    
    db.session.delete(dataset)
    db.session.commit()
    
    return flask.Response(status=204)
