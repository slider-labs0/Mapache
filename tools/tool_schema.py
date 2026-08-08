"""
tool_schema.py - Tool argument validation

Validates tool call arguments against JSON schemas before execution.
Prevents bad args from reaching tools and gives the model clear error feedback.
"""

from __future__ import annotations

import json
from typing import Any, Optional


class SchemaValidationError(Exception):
    def __init__(self, tool_name: str, errors: list[str]) -> None:
        self.tool_name = tool_name
        self.errors = errors
        super().__init__(f"{tool_name}: {'; '.join(errors)}")


def validate_args(
    tool_name: str,
    schema: dict[str, Any],
    args: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate and coerce tool arguments against a JSON schema.
    Returns validated args dict. Raises SchemaValidationError on failure.
    """
    errors: list[str] = []
    properties: dict = schema.get("properties", {})
    required: list[str] = schema.get("required", [])

    # Check required fields
    for field in required:
        if field not in args:
            errors.append(f"missing required argument '{field}'")

    if errors:
        raise SchemaValidationError(tool_name, errors)

    validated: dict[str, Any] = {}

    for key, prop_schema in properties.items():
        # A null for an optional field means "not provided" - local models
        # routinely dump every optional param with a null value. Treat it like
        # an omitted key (apply the default if any) rather than trying to coerce
        # None to the declared type, which would spuriously reject the call.
        if key not in args or (args[key] is None and key not in required):
            if "default" in prop_schema:
                validated[key] = prop_schema["default"]
            continue

        value = args[key]
        expected_type = prop_schema.get("type")

        try:
            value = _coerce(value, expected_type)
        except (ValueError, TypeError) as exc:
            errors.append(f"argument '{key}': {exc}")
            continue

        if "enum" in prop_schema and value not in prop_schema["enum"]:
            errors.append(
                f"argument '{key}': must be one of {prop_schema['enum']}, got {value!r}"
            )
            continue

        validated[key] = value

    if errors:
        raise SchemaValidationError(tool_name, errors)

    return validated


def _coerce(value: Any, expected_type: Optional[str]) -> Any:
    if expected_type is None:
        return value
    if expected_type == "string":
        return str(value) if not isinstance(value, str) else value
    if expected_type == "integer":
        if isinstance(value, bool):
            raise TypeError("expected integer, got boolean")
        return int(value)
    if expected_type == "number":
        if isinstance(value, bool):
            raise TypeError("expected number, got boolean")
        return float(value)
    if expected_type == "boolean":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            if value.lower() in ("true", "1", "yes"):
                return True
            if value.lower() in ("false", "0", "no"):
                return False
            raise ValueError(f"cannot coerce {value!r} to boolean")
        return bool(value)
    if expected_type == "array":
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    return parsed
            except json.JSONDecodeError:
                pass
        raise TypeError(f"expected array, got {type(value).__name__}")
    if expected_type == "object":
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                pass
        raise TypeError(f"expected object, got {type(value).__name__}")
    return value
