"""
SCIM serializers for converting between SCIM JSON and internal models.
"""

from typing import Any, Dict, List, Optional

from ..model.dataset import Dataset
from ..model.group import Group
from ..model.group_dataset_permission import GroupDatasetPermission
from ..model.table_mapping import ServiceTable
from ..model.user import User
from .utils import format_datetime, generate_scim_id, get_base_url


class UserSCIMSerializer:
    """Serializer for User ↔ SCIM User resource."""
    
    USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
    EXTENSION_SCHEMA = "urn:ietf:params:scim:schemas:extension:neuroglancer:2.0:User"
    
    @staticmethod
    def to_scim(user: User, include_permissions: bool = False) -> Dict[str, Any]:
        """
        Convert User model to SCIM User resource.
        
        Args:
            user: User model instance
            include_permissions: Whether to include computed permissions (read-only)
            
        Returns:
            SCIM User resource dictionary
        """
        base_url = get_base_url()
        # Use stored scim_id if available, otherwise generate
        scim_id = user.scim_id or generate_scim_id(user.id, "User")
        
        # Store scim_id if not already stored
        if not user.scim_id:
            user.scim_id = scim_id
            from ..model.base import db
            db.session.commit()
        
        # Parse name (simple approach: use full name as givenName)
        # In production, you might want to store givenName/familyName separately
        name_parts = user.name.split(" ", 1) if user.name else ["", ""]
        given_name = name_parts[0] if name_parts else ""
        family_name = name_parts[1] if len(name_parts) > 1 else ""
        
        resource = {
            "schemas": [UserSCIMSerializer.USER_SCHEMA],
            "id": scim_id,
            "externalId": user.external_id,  # Include externalId if set
            "userName": user.email,
            "name": {
                "formatted": user.public_name,
                "familyName": family_name,
                "givenName": given_name,
            },
            "displayName": user.public_name,
            "emails": [
                {
                    "value": user.email,
                    "type": "work",
                    "primary": True,
                }
            ],
            "active": True,  # Users are active if they exist
            "meta": {
                "resourceType": "User",
                "created": format_datetime(user.created),
                "lastModified": format_datetime(user.created),  # TODO: track lastModified
                "location": f"{base_url}/v2/Users/{scim_id}",
                "version": f'W/"scim-{user.id}"',  # Simple versioning
            },
        }
        
        # Add extension for Neuroglancer-specific attributes
        resource["schemas"].append(UserSCIMSerializer.EXTENSION_SCHEMA)
        resource[UserSCIMSerializer.EXTENSION_SCHEMA] = {
            "admin": user.admin,
            "pi": user.pi,
            "gdprConsent": user.gdpr_consent,
            "serviceAccount": user.is_service_account,
        }
        
        # Add groups
        groups = user.get_groups()
        resource["groups"] = [
            {
                "value": generate_scim_id(group["id"], "Group"),
                "$ref": f"{base_url}/v2/Groups/{generate_scim_id(group['id'], 'Group')}",
                "display": group["name"],
            }
            for group in groups
        ]
        
        # Optionally include computed permissions (read-only)
        if include_permissions:
            cache = user.create_cache()
            resource["urn:ietf:params:scim:schemas:neuroglancer:2.0:UserPermissions"] = {
                "permissions": cache.get("permissions_v2", {}),
                "datasetsAdmin": cache.get("datasets_admin", []),
                "groupsAdmin": cache.get("groups_admin", []),
            }
            resource["schemas"].append(
                "urn:ietf:params:scim:schemas:neuroglancer:2.0:UserPermissions"
            )
        
        return resource
    
    @staticmethod
    def from_scim(scim_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert SCIM User resource to internal format for User.create_account() or User.update().
        
        Args:
            scim_data: SCIM User resource dictionary
            
        Returns:
            Dictionary with keys matching User model fields
        """
        data = {}
        
        # Extract externalId (SCIM spec: external system identifier)
        if "externalId" in scim_data:
            data["external_id"] = scim_data["externalId"]
        
        # Extract email/userName
        if "userName" in scim_data:
            data["email"] = scim_data["userName"]
        elif "emails" in scim_data and len(scim_data["emails"]) > 0:
            data["email"] = scim_data["emails"][0].get("value")
        
        # Extract name
        if "name" in scim_data:
            name_obj = scim_data["name"]
            given = name_obj.get("givenName", "")
            family = name_obj.get("familyName", "")
            data["name"] = f"{given} {family}".strip() or name_obj.get("formatted", "")
        elif "displayName" in scim_data:
            data["name"] = scim_data["displayName"]
        
        # Extract extension attributes
        ext = scim_data.get(UserSCIMSerializer.EXTENSION_SCHEMA, {})
        if "admin" in ext:
            data["admin"] = ext["admin"]
        if "pi" in ext:
            data["pi"] = ext["pi"]
        if "gdprConsent" in ext:
            data["gdpr_consent"] = ext["gdprConsent"]
        
        # Extract active status (for soft delete)
        if "active" in scim_data and not scim_data["active"]:
            # Handle soft delete - for now, we'll skip inactive users
            pass
        
        return data


class GroupSCIMSerializer:
    """Serializer for Group ↔ SCIM Group resource."""
    
    GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
    PERMISSIONS_SCHEMA = (
        "urn:ietf:params:scim:schemas:neuroglancer:2.0:GroupPermissions"
    )
    
    @staticmethod
    def to_scim(
        group: Group, include_permissions: bool = True, include_members: bool = True
    ) -> Dict[str, Any]:
        """
        Convert Group model to SCIM Group resource.
        
        Args:
            group: Group model instance
            include_permissions: Whether to include dataset permissions
            include_members: Whether to include group members
            
        Returns:
            SCIM Group resource dictionary
        """
        base_url = get_base_url()
        # Use stored scim_id if available, otherwise generate
        scim_id = group.scim_id or generate_scim_id(group.id, "Group")
        
        # Store scim_id if not already stored
        if not group.scim_id:
            group.scim_id = scim_id
            from ..model.base import db
            db.session.commit()
        
        resource = {
            "schemas": [GroupSCIMSerializer.GROUP_SCHEMA],
            "id": scim_id,
            "externalId": group.external_id,  # Include externalId if set
            "displayName": group.name,
            "meta": {
                "resourceType": "Group",
                "created": format_datetime(None),  # TODO: track created date
                "lastModified": format_datetime(None),
                "location": f"{base_url}/v2/Groups/{scim_id}",
                "version": f'W/"scim-{group.id}"',
            },
        }
        
        # Add members
        if include_members:
            from ..model.user_group import UserGroup
            
            members = UserGroup.get_member_list(group.id)
            resource["members"] = [
                {
                    "value": generate_scim_id(member["id"], "User"),
                    "$ref": f"{base_url}/v2/Users/{generate_scim_id(member['id'], 'User')}",
                    "display": member["name"],
                }
                for member in members
            ]
        
        # Add dataset permissions extension
        if include_permissions:
            permissions = GroupDatasetPermission.get_permissions_for_group(group.id)
            
            # Group permissions by dataset
            dataset_perms = {}
            for perm in permissions:
                dataset_id = perm["id"]
                if dataset_id not in dataset_perms:
                    dataset_perms[dataset_id] = {
                        "datasetId": generate_scim_id(dataset_id, "Dataset"),
                        "datasetName": perm["name"],
                        "permissions": [],
                    }
                dataset_perms[dataset_id]["permissions"].append(perm["permission"])
            
            if dataset_perms:
                resource["schemas"].append(GroupSCIMSerializer.PERMISSIONS_SCHEMA)
                resource[GroupSCIMSerializer.PERMISSIONS_SCHEMA] = {
                    "datasetPermissions": list(dataset_perms.values())
                }
        
        return resource
    
    @staticmethod
    def from_scim(scim_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert SCIM Group resource to internal format.
        
        Args:
            scim_data: SCIM Group resource dictionary
            
        Returns:
            Dictionary with keys matching Group model fields
        """
        data = {}
        
        # Extract externalId
        if "externalId" in scim_data:
            data["external_id"] = scim_data["externalId"]
        
        if "displayName" in scim_data:
            data["name"] = scim_data["displayName"]
        
        return data


class DatasetSCIMSerializer:
    """Serializer for Dataset ↔ SCIM Dataset resource (custom resource type)."""
    
    DATASET_SCHEMA = "urn:ietf:params:scim:schemas:neuroglancer:2.0:Dataset"
    
    @staticmethod
    def to_scim(dataset: Dataset) -> Dict[str, Any]:
        """
        Convert Dataset model to SCIM Dataset resource.
        
        Args:
            dataset: Dataset model instance
            
        Returns:
            SCIM Dataset resource dictionary
        """
        base_url = get_base_url()
        # Use stored scim_id if available, otherwise generate
        scim_id = dataset.scim_id or generate_scim_id(dataset.id, "Dataset")
        
        # Store scim_id if not already stored
        if not dataset.scim_id:
            dataset.scim_id = scim_id
            from ..model.base import db
            db.session.commit()
        
        # Get ServiceTable mappings
        service_tables = ServiceTable.query.filter_by(dataset_id=dataset.id).all()
        
        resource = {
            "schemas": [DatasetSCIMSerializer.DATASET_SCHEMA],
            "id": scim_id,
            "externalId": dataset.external_id,  # Include externalId if set
            "name": dataset.name,
            "tosId": dataset.tos_id,
            "serviceTables": [
                {
                    "serviceName": st.service_name,
                    "tableName": st.table_name,
                    "datasetId": scim_id,
                }
                for st in service_tables
            ],
            "meta": {
                "resourceType": "Dataset",
                "created": format_datetime(None),  # TODO: track created date
                "lastModified": format_datetime(None),
                "location": f"{base_url}/v2/Datasets/{scim_id}",
                "version": f'W/"scim-{dataset.id}"',
            },
        }
        
        return resource
    
    @staticmethod
    def from_scim(scim_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert SCIM Dataset resource to internal format.
        
        Args:
            scim_data: SCIM Dataset resource dictionary
            
        Returns:
            Dictionary with keys matching Dataset model fields
        """
        data = {}
        
        # Extract externalId
        if "externalId" in scim_data:
            data["external_id"] = scim_data["externalId"]
        
        if "name" in scim_data:
            data["name"] = scim_data["name"]
        
        if "tosId" in scim_data:
            data["tos_id"] = scim_data["tosId"]
        
        return data
