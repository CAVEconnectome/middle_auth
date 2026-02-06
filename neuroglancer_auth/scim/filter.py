"""
SCIM filter parser and query builder.

Supports SCIM filter expressions as defined in RFC 7644 §3.4.2.2.
"""

from typing import Any, Callable, Dict, List, Optional, Tuple

from sqlalchemy import and_, or_, not_
from sqlalchemy.orm import Query


class SCIMFilterParser:
    """Parser for SCIM filter expressions."""
    
    # SCIM filter operators
    OPERATORS = {
        "eq": lambda attr, val: attr == val,
        "ne": lambda attr, val: attr != val,
        "co": lambda attr, val: attr.ilike(f"%{val}%"),  # contains (case-insensitive)
        "sw": lambda attr, val: attr.ilike(f"{val}%"),  # starts with
        "ew": lambda attr, val: attr.ilike(f"%{val}"),  # ends with
        "pr": lambda attr, val: attr.isnot(None),  # present (value ignored)
        "gt": lambda attr, val: attr > val,
        "ge": lambda attr, val: attr >= val,
        "lt": lambda attr, val: attr < val,
        "le": lambda attr, val: attr <= val,
    }
    
    @staticmethod
    def parse_filter(filter_expr: str) -> Tuple[str, str, str]:
        """
        Parse a simple SCIM filter expression.
        
        Format: attribute operator "value"
        Example: userName eq "user@example.com"
        
        Args:
            filter_expr: SCIM filter expression
            
        Returns:
            Tuple of (attribute, operator, value)
        """
        # Simple parser - handles basic cases
        # For full SCIM filter support, consider using a proper parser library
        
        # Remove quotes from value
        filter_expr = filter_expr.strip()
        
        # Find operator
        for op in SCIMFilterParser.OPERATORS.keys():
            if f" {op} " in filter_expr:
                parts = filter_expr.split(f" {op} ", 1)
                if len(parts) == 2:
                    attr = parts[0].strip()
                    val = parts[1].strip().strip('"').strip("'")
                    return (attr, op, val)
        
        raise ValueError(f"Invalid filter expression: {filter_expr}")
    
    @staticmethod
    def apply_user_filter(query: Query, filter_expr: str) -> Query:
        """
        Apply SCIM filter to User query.
        
        Args:
            query: SQLAlchemy query for User
            filter_expr: SCIM filter expression
            
        Returns:
            Modified query
        """
        from ..model.user import User
        
        # Map SCIM attributes to User model attributes
        attr_map = {
            "userName": User.email,
            "emails.value": User.email,
            "name.givenName": User.name,  # Simplified - full name matching
            "name.familyName": User.name,
            "displayName": User.name,
            "active": None,  # Always true for existing users
        }
        
        try:
            attr_name, operator, value = SCIMFilterParser.parse_filter(filter_expr)
            
            # Handle complex filters (and/or/not) - simplified for now
            # Use case-insensitive search but preserve original case for attribute names
            filter_lower = filter_expr.lower()
            if " and " in filter_lower:
                # Find the actual case of " and " in the original string
                and_pos = filter_lower.find(" and ")
                and_str = filter_expr[and_pos:and_pos+5]  # Preserve original case
                parts = filter_expr.split(and_str)
                conditions = []
                for part in parts:
                    try:
                        a, o, v = SCIMFilterParser.parse_filter(part.strip())
                        if a in attr_map and attr_map[a] is not None:
                            op_func = SCIMFilterParser.OPERATORS[o]
                            conditions.append(op_func(attr_map[a], v))
                    except ValueError:
                        pass
                if conditions:
                    query = query.filter(and_(*conditions))
            elif " or " in filter_lower:
                # Find the actual case of " or " in the original string
                or_pos = filter_lower.find(" or ")
                or_str = filter_expr[or_pos:or_pos+4]  # Preserve original case
                parts = filter_expr.split(or_str)
                conditions = []
                for part in parts:
                    try:
                        a, o, v = SCIMFilterParser.parse_filter(part.strip())
                        if a in attr_map and attr_map[a] is not None:
                            op_func = SCIMFilterParser.OPERATORS[o]
                            conditions.append(op_func(attr_map[a], v))
                    except ValueError:
                        pass
                if conditions:
                    query = query.filter(or_(*conditions))
            else:
                # Simple filter
                if attr_name in attr_map and attr_map[attr_name] is not None:
                    op_func = SCIMFilterParser.OPERATORS[operator]
                    query = query.filter(op_func(attr_map[attr_name], value))
        except (ValueError, KeyError):
            # Invalid filter - return query as-is (or raise error)
            pass
        
        return query
    
    @staticmethod
    def apply_group_filter(query: Query, filter_expr: str) -> Query:
        """
        Apply SCIM filter to Group query.
        
        Args:
            query: SQLAlchemy query for Group
            filter_expr: SCIM filter expression
            
        Returns:
            Modified query
        """
        from ..model.group import Group
        
        attr_map = {
            "displayName": Group.name,
            "id": Group.id,
        }
        
        try:
            attr_name, operator, value = SCIMFilterParser.parse_filter(filter_expr)
            
            if attr_name in attr_map:
                op_func = SCIMFilterParser.OPERATORS[operator]
                query = query.filter(op_func(attr_map[attr_name], value))
        except (ValueError, KeyError):
            pass
        
        return query
    
    @staticmethod
    def apply_dataset_filter(query: Query, filter_expr: str) -> Query:
        """
        Apply SCIM filter to Dataset query.
        
        Args:
            query: SQLAlchemy query for Dataset
            filter_expr: SCIM filter expression
            
        Returns:
            Modified query
        """
        from ..model.dataset import Dataset
        
        attr_map = {
            "name": Dataset.name,
            "id": Dataset.id,
            "tosId": Dataset.tos_id,
        }
        
        try:
            attr_name, operator, value = SCIMFilterParser.parse_filter(filter_expr)
            
            if attr_name in attr_map:
                op_func = SCIMFilterParser.OPERATORS[operator]
                query = query.filter(op_func(attr_map[attr_name], value))
        except (ValueError, KeyError):
            pass
        
        return query
