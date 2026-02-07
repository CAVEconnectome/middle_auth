"""
SCIM utility functions for ID conversion, error handling, and response formatting.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import flask


# UUID namespace for deterministic ID conversion
SCIM_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


class SCIMPaginationError(Exception):
    """Exception for invalid SCIM pagination parameters."""
    pass


def generate_scim_id(internal_id: int, resource_type: str) -> str:
    """
    Convert internal integer ID to SCIM-compliant UUID string.
    
    Uses UUID5 for deterministic mapping (same internal ID + resource type always maps to same UUID).
    Incorporates resource_type to ensure uniqueness across all resource types per RFC 7643 §3.1.
    
    Args:
        internal_id: Internal integer ID
        resource_type: Resource type (e.g., "User", "Group", "Dataset")
        
    Returns:
        UUID string in SCIM format
    """
    return str(uuid.uuid5(SCIM_NAMESPACE, f"{resource_type}:{internal_id}"))


def find_user_by_scim_identifier(scim_id: str = None, external_id: str = None):
    """
    Find User by SCIM identifier (scim_id or external_id).
    
    Priority: external_id (if provided) > scim_id (if provided)
    
    Args:
        scim_id: SCIM UUID string
        external_id: External system identifier
        
    Returns:
        User model instance or None
    """
    from ..model.user import User
    
    # Priority 1: Lookup by external_id if provided
    if external_id:
        user = User.query.filter_by(external_id=external_id).first()
        if user:
            return user
    
    # Priority 2: Lookup by scim_id if provided
    if scim_id:
        user = User.query.filter_by(scim_id=scim_id).first()
        if user:
            return user
    
    return None


def find_group_by_scim_identifier(scim_id: str = None, external_id: str = None):
    """
    Find Group by SCIM identifier.
    
    Args:
        scim_id: SCIM UUID string
        external_id: External system identifier
        
    Returns:
        Group model instance or None
    """
    from ..model.group import Group
    
    if external_id:
        group = Group.query.filter_by(external_id=external_id).first()
        if group:
            return group
    
    if scim_id:
        group = Group.query.filter_by(scim_id=scim_id).first()
        if group:
            return group
    
    return None


def find_dataset_by_scim_identifier(scim_id: str = None, external_id: str = None):
    """Find Dataset by SCIM identifier."""
    from ..model.dataset import Dataset
    
    if external_id:
        dataset = Dataset.query.filter_by(external_id=external_id).first()
        if dataset:
            return dataset
    
    if scim_id:
        dataset = Dataset.query.filter_by(scim_id=scim_id).first()
        if dataset:
            return dataset
    
    return None


def build_list_response(
    resources: List[Dict[str, Any]],
    total_results: int,
    start_index: int = 1,
    count: int = None,
) -> Dict[str, Any]:
    """
    Build SCIM ListResponse format.
    
    Args:
        resources: List of SCIM resource objects
        total_results: Total number of results
        start_index: 1-based index of first result
        count: Number of results in this response
        
    Returns:
        SCIM ListResponse dictionary
    """
    if count is None:
        count = len(resources)
    
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total_results,
        "itemsPerPage": count,
        "startIndex": start_index,
        "Resources": resources,
    }


def build_error_response(
    status: int,
    scim_type: str = None,
    detail: str = None,
) -> flask.Response:
    """
    Build SCIM Error response.
    
    Args:
        status: HTTP status code
        scim_type: SCIM error type (e.g., "invalidValue", "uniqueness")
        detail: Error detail message
        
    Returns:
        Flask Response with SCIM error format
    """
    error = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": str(status),
    }
    
    if scim_type:
        error["scimType"] = scim_type
    
    if detail:
        error["detail"] = detail
    
    response = flask.jsonify(error)
    response.status_code = status
    response.headers["Content-Type"] = "application/scim+json"
    return response


def parse_pagination_params() -> tuple[int, int]:
    """
    Parse SCIM pagination parameters from request.
    
    Returns:
        Tuple of (start_index, count)
        start_index is 1-based, defaults to 1
        count is number of results, defaults to 100
        count=0 is valid per RFC 7644 §3.4.2.4 (returns only totalResults)
        
    Raises:
        SCIMPaginationError: If startIndex or count are invalid (non-numeric or negative)
    """
    start_index_str = flask.request.args.get("startIndex")
    count_str = flask.request.args.get("count")
    
    # Parse startIndex with error handling
    if start_index_str is None:
        start_index = 1
    else:
        try:
            start_index = int(start_index_str)
        except ValueError:
            raise SCIMPaginationError(
                f"Invalid startIndex parameter: '{start_index_str}'. Must be a positive integer."
            )
    
    # Parse count with error handling
    if count_str is None:
        count = 100
    else:
        try:
            count = int(count_str)
        except ValueError:
            raise SCIMPaginationError(
                f"Invalid count parameter: '{count_str}'. Must be a non-negative integer."
            )
    
    # SCIM spec: startIndex is 1-based
    if start_index < 1:
        start_index = 1
    
    # Validate count: allow 0 (RFC 7644 §3.4.2.4), reject negative values
    if count < 0:
        raise SCIMPaginationError(
            f"Invalid count parameter: '{count}'. Must be a non-negative integer."
        )
    
    # Limit max count
    if count > 1000:
        count = 1000
    
    return start_index, count


def format_datetime(dt: Optional[datetime]) -> Optional[str]:
    """
    Format datetime to SCIM ISO 8601 format.
    
    Args:
        dt: Datetime object or None
        
    Returns:
        ISO 8601 string or None
    """
    if dt is None:
        return None
    return dt.isoformat() + "Z" if dt.tzinfo is None else dt.isoformat()


def get_base_url() -> str:
    """
    Get base URL for SCIM endpoints (for meta.location).
    
    Returns:
        Base URL string (e.g., http://host:port/{URL_PREFIX}/scim)
    """
    import os
    
    base_url = os.environ.get("SCIM_BASE_URL")
    if base_url:
        return base_url.rstrip("/")
    
    # Fallback: construct from request URL + URL_PREFIX + blueprint prefix
    # The blueprint prefix is /{URL_PREFIX}/scim/v2, but we need base_url without /v2
    # since location URLs are built as {base_url}/v2/Users/{id}
    url_prefix = os.environ.get("URL_PREFIX", "auth")
    request_root = flask.request.url_root.rstrip("/")
    return f"{request_root}/{url_prefix}/scim"


def create_user_with_scim(**kwargs):
    """
    Helper function to create a User with SCIM fields automatically set.
    
    This keeps SCIM logic out of the User model while making SCIM routes cleaner.
    
    Args:
        **kwargs: Arguments to pass to User.create_account()
        
    Returns:
        User instance with scim_id set
    """
    from ..model.user import User
    from ..model.base import db
    
    # Extract SCIM-specific args
    external_id = kwargs.pop("external_id", None)
    
    # Create user
    user = User.create_account(**kwargs, external_id=external_id)
    
    # Set scim_id after user is created (needs actual user.id)
    user.scim_id = generate_scim_id(user.id, "User")
    db.session.commit()
    
    return user


def create_group_with_scim(**kwargs):
    """
    Helper function to create a Group with SCIM fields automatically set.
    
    Args:
        **kwargs: Arguments to pass to Group.add()
        
    Returns:
        Group instance with scim_id set
    """
    from ..model.group import Group
    from ..model.base import db
    
    # Extract SCIM-specific args
    external_id = kwargs.pop("external_id", None)
    scim_id = kwargs.pop("scim_id", None)  # Will be set after creation
    
    # Create group
    group = Group.add(**kwargs, external_id=external_id, scim_id=scim_id)
    
    # Set scim_id after group is created
    group.scim_id = generate_scim_id(group.id, "Group")
    db.session.commit()
    
    return group


def create_dataset_with_scim(**kwargs):
    """
    Helper function to create a Dataset with SCIM fields automatically set.
    
    Args:
        **kwargs: Arguments to pass to Dataset.add()
        
    Returns:
        Dataset instance with scim_id set
    """
    from ..model.dataset import Dataset
    from ..model.base import db
    
    # Extract SCIM-specific args
    external_id = kwargs.pop("external_id", None)
    scim_id = kwargs.pop("scim_id", None)  # Will be set after creation
    
    # Create dataset
    dataset = Dataset.add(**kwargs, external_id=external_id, scim_id=scim_id)
    
    # Set scim_id after dataset is created
    dataset.scim_id = generate_scim_id(dataset.id, "Dataset")
    db.session.commit()
    
    return dataset
