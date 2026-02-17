"""
Test configuration for SCIM testing.

This file is used when running tests via Docker Compose.
It provides minimal configuration needed for SCIM API testing.
"""

import os

# Database configuration
SQLALCHEMY_DATABASE_URI = os.environ.get(
    "SQLALCHEMY_DATABASE_URI",
    "postgresql://scim_test:scim_test_password@postgres:5432/scim_test"
)

# Redis configuration
REDISHOST = os.environ.get("REDISHOST", "redis")
REDISPORT = int(os.environ.get("REDISPORT", 6379))

# Flask configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "test-secret-key-change-in-production")
DEBUG = os.environ.get("FLASK_ENV") == "development"
TESTING = True

# SQLAlchemy configuration
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ECHO = False  # Set to True for SQL query logging

# Session configuration (optional for testing)
SESSION_TYPE = None  # Disable sessions for testing

# SCIM configuration
SCIM_ENABLED = os.environ.get("SCIM_ENABLED", "true").lower() == "true"
SCIM_BASE_URL = os.environ.get("SCIM_BASE_URL", "http://localhost:5000/v2")

# Sticky auth (admin panel) - disabled for testing
STICKY_AUTH = os.environ.get("STICKY_AUTH", "false").lower() == "true"

# Default admins (optional - can be empty for testing)
DEFAULT_ADMINS = []

# OAuth configuration (optional for SCIM testing)
# These can be dummy values if OAuth endpoints aren't being tested
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
