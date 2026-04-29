"""
Parses MCP server definitions into structured tool profiles.
Supports: JSON manifest, Python source files, and in-memory dicts.
"""

import ast
import json
import re
from pathlib import Path
from typing import Any, Optional


def _extract_docstring(node: Any) -> Optional[str]:
    if (
        node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    ):
        return node.body[0].value.value.strip()
    return None


def _schema_from_annotations(node: Any) -> dict:
    props: dict[str, Any] = {}
    required: list[str] = []
    for arg in node.args.args:
        if arg.arg == "self":
            continue
        type_str = "string"
        if arg.annotation:
            if isinstance(arg.annotation, ast.Name):
                mapping = {"int": "integer", "float": "number", "bool": "boolean", "str": "string", "dict": "object", "list": "array"}
                type_str = mapping.get(arg.annotation.id, "string")
            elif isinstance(arg.annotation, ast.Attribute):
                type_str = "string"
        props[arg.arg] = {"type": type_str}
    # args without defaults are required
    n_defaults = len(node.args.defaults)
    n_args = len([a for a in node.args.args if a.arg != "self"])
    required = [a.arg for a in node.args.args if a.arg != "self"][:n_args - n_defaults]
    return {"type": "object", "properties": props, "required": required}


def from_dict(tool: dict[str, Any]) -> dict[str, Any]:
    """Normalize an already-structured tool dict into a canonical profile."""
    return {
        "tool_id": tool.get("tool_id", tool.get("name", "unknown")),
        "tool_name": tool.get("tool_name", tool.get("name", "")),
        "tool_description": tool.get("tool_description", tool.get("description", "")),
        "tool_schema": tool.get("tool_schema", tool.get("inputSchema", tool.get("schema", {}))),
        "docstrings": tool.get("docstrings", []),
        "source": "dict",
    }


def from_json_manifest(path: Any) -> list:
    """Parse an MCP server JSON manifest and return a list of tool profiles."""
    data = json.loads(Path(path).read_text())

    # Handle various manifest shapes
    tools_raw: list[dict[str, Any]] = []
    if isinstance(data, list):
        tools_raw = data
    elif "tools" in data:
        tools_raw = data["tools"]
    elif "entries" in data:
        # This is our corpus labels.json — return corpus-format profiles
        return [from_dict(e) for e in data["entries"]]
    else:
        tools_raw = [data]

    return [from_dict(t) for t in tools_raw]


def from_python_source(path: Any) -> list:
    """
    Parses Python source for functions decorated with @mcp.tool or @tool,
    or any async def / def that looks like an MCP tool handler.
    """
    source = Path(path).read_text()
    tree = ast.parse(source)
    profiles: list[dict[str, Any]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        is_tool = any(
            (isinstance(d, ast.Name) and d.id in ("tool", "mcp_tool"))
            or (isinstance(d, ast.Attribute) and d.attr in ("tool", "mcp_tool"))
            or (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "tool")
            for d in node.decorator_list
        )
        if not is_tool:
            continue

        docstring = _extract_docstring(node)
        schema = _schema_from_annotations(node)

        profiles.append({
            "tool_id": f"{Path(path).stem}_{node.name}",
            "tool_name": node.name,
            "tool_description": docstring or "",
            "tool_schema": schema,
            "docstrings": [docstring] if docstring else [],
            "source": str(path),
        })

    return profiles


def from_server_url(server_info: dict) -> list:
    """
    Normalizes a tool list returned by an MCP list_tools response.
    server_info should be {"tools": [...list_tools result...]}
    """
    tools = server_info.get("tools", [])
    return [
        {
            "tool_id": f"remote_{t.get('name', 'unknown')}",
            "tool_name": t.get("name", ""),
            "tool_description": t.get("description", ""),
            "tool_schema": t.get("inputSchema", {}),
            "docstrings": [],
            "source": "remote",
        }
        for t in tools
    ]


def load_corpus_profiles(corpus_path: Optional[Path] = None) -> list:
    """Load all tool profiles from the corpus labels.json."""
    if corpus_path is None:
        corpus_path = Path(__file__).parent.parent / "corpus" / "labels.json"
    data = json.loads(corpus_path.read_text())
    return [from_dict(e) for e in data["entries"]]
