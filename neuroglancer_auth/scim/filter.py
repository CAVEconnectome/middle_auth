"""
SCIM filter parser and query builder.

Supports SCIM filter expressions as defined in RFC 7644 §3.4.2.2.
Uses scim2-filter-parser for robust, RFC-compliant parsing.
"""

from typing import Any, Dict, Optional

from sqlalchemy import and_, or_, not_
from sqlalchemy.orm import Query

from scim2_filter_parser.parser import Parser as SCIMParser



class SCIMFilterParser:
    """Parser for SCIM filter expressions using scim2-filter-parser."""
    
    # SCIM filter operators mapped to SQLAlchemy conditions
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
    def _ast_to_sqlalchemy(
        ast_node: Any,
        attr_map: Dict[str, Any],
        query: Query
    ) -> Optional[Any]:
        """
        Convert SCIM AST node to SQLAlchemy condition.
        
        Args:
            ast_node: AST node from scim2-filter-parser
            attr_map: Mapping of SCIM attribute names to SQLAlchemy model attributes
            query: SQLAlchemy query object
            
        Returns:
            SQLAlchemy condition or None if attribute not mapped
        """
        # Check for attribute expression (has attribute_path, operator, comp_value)
        if hasattr(ast_node, 'attribute_path') and hasattr(ast_node, 'operator'):
            # Attribute comparison: attr operator value
            attr_name = ast_node.attribute_path
            operator = ast_node.operator
            value = getattr(ast_node, 'comp_value', None)
            
            # Map SCIM attribute to SQLAlchemy attribute
            if attr_name not in attr_map or attr_map[attr_name] is None:
                return None
            
            sqlalchemy_attr = attr_map[attr_name]
            
            # Get operator function
            if operator not in SCIMFilterParser.OPERATORS:
                return None
            
            op_func = SCIMFilterParser.OPERATORS[operator]
            
            # Convert value if needed (handle boolean/None)
            if value is None:
                # For "pr" operator, value is ignored
                if operator == "pr":
                    return op_func(sqlalchemy_attr, None)
                return None
            
            # Handle boolean strings
            if isinstance(value, str):
                if value.lower() == "true":
                    value = True
                elif value.lower() == "false":
                    value = False
            
            return op_func(sqlalchemy_attr, value)
        
        # Check for logical expression (has left, right, operator)
        elif hasattr(ast_node, 'left') and hasattr(ast_node, 'right') and hasattr(ast_node, 'operator'):
            # Logical operator: and/or
            left = SCIMFilterParser._ast_to_sqlalchemy(ast_node.left, attr_map, query)
            right = SCIMFilterParser._ast_to_sqlalchemy(ast_node.right, attr_map, query)
            
            if left is None and right is None:
                return None
            if left is None:
                return right
            if right is None:
                return left
            
            operator = ast_node.operator
            if operator == "and":
                return and_(left, right)
            elif operator == "or":
                return or_(left, right)
            else:
                return None
        
        # Check for not expression (has expression attribute but not left/right)
        elif hasattr(ast_node, 'expression') and not (hasattr(ast_node, 'left') and hasattr(ast_node, 'right')):
            # Not operator
            condition = SCIMFilterParser._ast_to_sqlalchemy(ast_node.expression, attr_map, query)
            if condition is None:
                return None
            return not_(condition)
        
        return None
    
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
        

        parser = SCIMParser()
        ast = parser.parse(filter_expr)
        
        condition = SCIMFilterParser._ast_to_sqlalchemy(ast, attr_map, query)
        if condition is not None:
            query = query.filter(condition)

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

        parser = SCIMParser()
        ast = parser.parse(filter_expr)
        
        condition = SCIMFilterParser._ast_to_sqlalchemy(ast, attr_map, query)
        if condition is not None:
            query = query.filter(condition)
        
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
        
        parser = SCIMParser()
        ast = parser.parse(filter_expr)
        
        condition = SCIMFilterParser._ast_to_sqlalchemy(ast, attr_map, query)
        if condition is not None:
            query = query.filter(condition)
        
        return query
