"""
SCIM filter parser and query builder.

Supports SCIM filter expressions as defined in RFC 7644 §3.4.2.2.
Uses scim2-filter-parser for robust, RFC-compliant parsing.
"""

from typing import Any, Dict, Optional

from sqlalchemy import and_, or_, not_
from sqlalchemy.orm import Query

import logging
import threading

from scim2_filter_parser.lexer import SCIMLexer
from scim2_filter_parser.parser import SCIMParser


# Create module-level lexer and parser instances (singleton pattern)
# SLY parsers need to be instantiated once and reused
# Use a lock to ensure thread-safe initialization
_lexer_instance = None
_parser_instance = None
_parser_lock = threading.Lock()


def _get_lexer():
    """Get or create the lexer instance (thread-safe)."""
    global _lexer_instance
    if _lexer_instance is None:
        with _parser_lock:
            if _lexer_instance is None:
                _lexer_instance = SCIMLexer()
    return _lexer_instance


def _get_parser():
    """Get or create the parser instance (thread-safe)."""
    global _parser_instance
    # Double-checked locking pattern for thread safety
    if _parser_instance is None:
        with _parser_lock:
            if _parser_instance is None:
                _parser_instance = SCIMParser()
    return _parser_instance


class SCIMFilterError(Exception):
    """Exception for invalid SCIM filter expressions."""
    pass


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
            ast_node: AST node from scim2-filter-parser (Filter object)
            attr_map: Mapping of SCIM attribute names to SQLAlchemy model attributes
            query: SQLAlchemy query object
            
        Returns:
            SQLAlchemy condition or None if attribute not mapped
        """
        # Handle negated (NOT) expressions first
        # Filter(expr=..., negated=True) means the expression is negated
        is_negated = getattr(ast_node, 'negated', False)
        
        # Get the inner expression
        if not hasattr(ast_node, 'expr'):
            return None
        
        expr = ast_node.expr
        
        # Check for AttrExpr (attribute comparison: userName eq "value")
        if hasattr(expr, 'attr_path') and hasattr(expr, 'value'):
            # Extract attribute name from AttrPath object
            attr_path_obj = expr.attr_path
            
            # Try multiple ways to extract the attribute path string
            if hasattr(attr_path_obj, 'attr_name'):
                attr_name = attr_path_obj.attr_named
            elif isinstance(attr_path_obj, str):
                attr_name = attr_path_obj
            elif hasattr(attr_path_obj, 'value'):
                attr_name = attr_path_obj.value
            else:
                raise ValueError(f"Invalid attribute path: {attr_path_obj} dir: {dir(attr_path_obj)}")
                
            
            # Operator is already a string (e.g., 'eq', 'ne', 'co')
            operator = expr.value
            
            # Extract comparison value from CompValue object
            comp_value_obj = getattr(expr, 'comp_value', None)
            if comp_value_obj is not None:
                if hasattr(comp_value_obj, 'value'):
                    value = comp_value_obj.value
                elif hasattr(comp_value_obj, 'val'):
                    value = comp_value_obj.val
                else:
                    # Try string conversion as fallback
                    value = str(comp_value_obj)
            else:
                value = None
            
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
                    condition = op_func(sqlalchemy_attr, None)
                else:
                    return None
            else:
                # Handle boolean strings
                if isinstance(value, str):
                    if value.lower() == "true":
                        value = True
                    elif value.lower() == "false":
                        value = False
                
                condition = op_func(sqlalchemy_attr, value)
            
            # Apply negation if needed
            if is_negated:
                return not_(condition)
            return condition
        
        # Check for LogExpr (logical expression: and/or)
        # LogExpr(op='or', expr1=Filter, expr2=Filter)
        elif hasattr(expr, 'op') and hasattr(expr, 'expr1') and hasattr(expr, 'expr2'):
            # Recursively process left and right expressions
            left = SCIMFilterParser._ast_to_sqlalchemy(expr.expr1, attr_map, query)
            right = SCIMFilterParser._ast_to_sqlalchemy(expr.expr2, attr_map, query)
            
            if left is None and right is None:
                result = None
            elif left is None:
                result = right
            elif right is None:
                result = left
            else:
                operator = expr.op
                if operator == "and":
                    result = and_(left, right)
                elif operator == "or":
                    result = or_(left, right)
                else:
                    result = None
            
            # Apply negation if needed
            if is_negated and result is not None:
                return not_(result)
            return result
        
        # Check for nested Filter (e.g., in parentheses or NOT)
        elif hasattr(expr, 'expr') or hasattr(expr, 'negated'):
            # Recursively process nested filter
            condition = SCIMFilterParser._ast_to_sqlalchemy(expr, attr_map, query)
            
            # Apply negation if needed
            if is_negated and condition is not None:
                return not_(condition)
            return condition
        
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
            
        Raises:
            SCIMFilterError: If filter expression is invalid
        """
        if not filter_expr or not filter_expr.strip():
            return query
        
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
            # Use lexer to tokenize the filter expression first, then parse the token stream
            lexer = _get_lexer()
            parser = _get_parser()
            token_stream = lexer.tokenize(filter_expr)
            ast = parser.parse(token_stream)
            
            condition = SCIMFilterParser._ast_to_sqlalchemy(ast, attr_map, query)
            if condition is not None:
                query = query.filter(condition)
        except Exception as e:
            # Re-raise as SCIMFilterError with details
            logger = logging.getLogger(__name__)
            logger.warning(f"Invalid SCIM filter expression: {filter_expr}, error: {str(e)}", exc_info=True)
            raise SCIMFilterError(f"Invalid filter expression: {str(e)}") from e

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
            
        Raises:
            SCIMFilterError: If filter expression is invalid
        """
        if not filter_expr or not filter_expr.strip():
            return query
        
        from ..model.group import Group
        
        attr_map = {
            "displayName": Group.name,
            "id": Group.id,
        }
        
        try:
            # Use lexer to tokenize the filter expression first, then parse the token stream
            lexer = _get_lexer()
            parser = _get_parser()
            token_stream = lexer.tokenize(filter_expr)
            ast = parser.parse(token_stream)
            
            condition = SCIMFilterParser._ast_to_sqlalchemy(ast, attr_map, query)
            if condition is not None:
                query = query.filter(condition)
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.warning(f"Invalid SCIM filter expression: {filter_expr}, error: {str(e)}", exc_info=True)
            raise SCIMFilterError(f"Invalid filter expression: {str(e)}") from e
        
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
            
        Raises:
            SCIMFilterError: If filter expression is invalid
        """
        if not filter_expr or not filter_expr.strip():
            return query
        
        from ..model.dataset import Dataset
        
        attr_map = {
            "name": Dataset.name,
            "id": Dataset.id,
            "tosId": Dataset.tos_id,
        }
        
        try:
            # Use lexer to tokenize the filter expression first, then parse the token stream
            lexer = _get_lexer()
            parser = _get_parser()
            token_stream = lexer.tokenize(filter_expr)
            ast = parser.parse(token_stream)
            
            condition = SCIMFilterParser._ast_to_sqlalchemy(ast, attr_map, query)
            if condition is not None:
                query = query.filter(condition)
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.warning(f"Invalid SCIM filter expression: {filter_expr}, error: {str(e)}", exc_info=True)
            raise SCIMFilterError(f"Invalid filter expression: {str(e)}") from e
        
        return query
