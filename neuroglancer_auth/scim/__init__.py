"""
SCIM 2.0 API implementation for Neuroglancer Auth.

This module provides SCIM 2.0 compliant endpoints for identity and
authorization management, including custom resource types for Datasets.
"""

from .routes import scim_bp

__all__ = ["scim_bp"]
