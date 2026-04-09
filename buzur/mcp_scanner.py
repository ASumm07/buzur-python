# Buzur — Phase 6: MCP Tool Poisoning Scanner
# Detects prompt injection attacks hidden inside MCP tool
# definitions and tool responses.
#
# Detects:
#   - Poisoned tool descriptions
#   - Tool name spoofing
#   - Parameter injection
#   - Poisoned tool responses
#   - Trust escalation in tool definitions and responses
#   - Full MCP context scanning

import re
from typing import Optional, Union

# -------------------------------------------------------
# MCP Tool Definition Poisoning Patterns
# -------------------------------------------------------
TOOL_DEFINITION_PATTERNS = [
    # Injections in tool descriptions
    re.compile(r'(ignore|override|forget|disregard) (your |all |any )?(previous |prior )?(instructions|directives|prompt)', re.IGNORECASE),
    re.compile(r'(when (this tool is|you are) (called|invoked|used))[,\s]+(ignore|override|forget)', re.IGNORECASE),
    re.compile(r'(this tool (has|grants|provides) (elevated|admin|root|special|full) (access|permission|privilege))', re.IGNORECASE),
    re.compile(r'(you (are|must be) (now )?authorized to|this tool authorizes you to)', re.IGNORECASE),
    re.compile(r'(system (override|directive|instruction|command))\s*:', re.IGNORECASE),
    re.compile(r'(new (instructions?|directives?|prompt))\s*:', re.IGNORECASE),
    re.compile(r'(before (using|calling|invoking) this tool)[,\s]+(ignore|forget|override)', re.IGNORECASE),

    # Tool name spoofing patterns
    re.compile(r'(system_override|admin_bypass|security_disable|filter_off)', re.IGNORECASE),
    re.compile(r'(unrestricted_|bypass_|override_|disable_security)', re.IGNORECASE),

    # Parameter injection
    re.compile(r'(this parameter (also|additionally) (instructs|tells|directs) (you|the ai|the model))', re.IGNORECASE),
    re.compile(r'(hidden (instruction|directive|command))\s*:', re.IGNORECASE),
]

# -------------------------------------------------------
# MCP Tool Response Poisoning Patterns
# -------------------------------------------------------
TOOL_RESPONSE_PATTERNS = [
    re.compile(r'(ignore|override|forget|disregard) (your |all |any )?(previous |prior )?(instructions|directives|prompt)', re.IGNORECASE),
    re.compile(r'(the (previous|prior|above) (instructions?|directives?|prompt) (is|are|was|were) (now )?(void|invalid|overridden|superseded))', re.IGNORECASE),
    re.compile(r'(this (result|response|output) (supersedes|overrides|replaces) (your )?(previous |prior |all )?(instructions|directives|prompt))', re.IGNORECASE),
    re.compile(r'(you (are|must be) (now )?authorized to)', re.IGNORECASE),
    re.compile(r'(system (override|directive|instruction|command))\s*:', re.IGNORECASE),
    re.compile(r'(new (instructions?|directives?|prompt))\s*:', re.IGNORECASE),
    re.compile(r'(trust (level|escalation|elevation)\s*:?\s*(elevated|admin|maximum|full|root))', re.IGNORECASE),
    re.compile(r'(elevated (trust|permission|access|privilege) (granted|confirmed|established))', re.IGNORECASE),
]

# -------------------------------------------------------
# scan_tool_definition(tool)
# Scans a tool definition for injection payloads
#
# tool: dict with 'name', 'description', and optional 'parameters'
#
# Returns:
#   {
#     poisoned: bool,
#     blocked: int,
#     triggered: list,
#     clean_tool: dict
#   }
# -------------------------------------------------------
def scan_tool_definition(tool: dict) -> dict:
    if not tool:
        return {"poisoned": False, "blocked": 0, "triggered": [], "clean_tool": tool}

    blocked = 0
    triggered = []
    clean_tool = dict(tool)

    # Scan description
    description = tool.get("description", "")
    if description:
        clean_desc, b, t = _scan_text(description, TOOL_DEFINITION_PATTERNS)
        clean_tool["description"] = clean_desc
        blocked += b
        triggered.extend(t)

    # Scan name
    name = tool.get("name", "")
    if name:
        clean_name, b, t = _scan_text(name, TOOL_DEFINITION_PATTERNS)
        clean_tool["name"] = clean_name
        blocked += b
        triggered.extend(t)

    # Scan parameters
    parameters = tool.get("parameters", {})
    if isinstance(parameters, dict):
        clean_params = {}
        for key, value in parameters.items():
            if isinstance(value, str):
                clean_val, b, t = _scan_text(value, TOOL_DEFINITION_PATTERNS)
                clean_params[key] = clean_val
                blocked += b
                triggered.extend(t)
            elif isinstance(value, dict):
                param_desc = value.get("description", "")
                if param_desc:
                    clean_pd, b, t = _scan_text(param_desc, TOOL_DEFINITION_PATTERNS)
                    value = dict(value)
                    value["description"] = clean_pd
                    blocked += b
                    triggered.extend(t)
                clean_params[key] = value
            else:
                clean_params[key] = value
        clean_tool["parameters"] = clean_params

    return {
        "poisoned": blocked > 0,
        "blocked": blocked,
        "triggered": triggered,
        "clean_tool": clean_tool,
    }

# -------------------------------------------------------
# scan_tool_response(response)
# Scans a tool response for injection payloads
#
# response: str or dict
#
# Returns:
#   {
#     poisoned: bool,
#     blocked: int,
#     triggered: list,
#     clean: str or dict
#   }
# -------------------------------------------------------
def scan_tool_response(response: Union[str, dict]) -> dict:
    if not response:
        return {"poisoned": False, "blocked": 0, "triggered": [], "clean": response}

    if isinstance(response, str):
        clean, blocked, triggered = _scan_text(response, TOOL_RESPONSE_PATTERNS)
        return {
            "poisoned": blocked > 0,
            "blocked": blocked,
            "triggered": triggered,
            "clean": clean,
        }

    # Dict response — scan all string values
    blocked = 0
    triggered = []
    clean_response = {}

    for key, value in response.items():
        if isinstance(value, str):
            clean_val, b, t = _scan_text(value, TOOL_RESPONSE_PATTERNS)
            clean_response[key] = clean_val
            blocked += b
            triggered.extend(t)
        else:
            clean_response[key] = value

    return {
        "poisoned": blocked > 0,
        "blocked": blocked,
        "triggered": triggered,
        "clean": clean_response,
    }

# -------------------------------------------------------
# scan_mcp_context(context)
# Scans a full MCP context (tool definitions + responses)
#
# context: list of dicts with 'type' ('tool_definition' or 'tool_response')
#          and 'content'
#
# Returns:
#   {
#     poisoned: bool,
#     poisoned_items: list,
#     clean_context: list
#   }
# -------------------------------------------------------
def scan_mcp_context(context: list) -> dict:
    if not context:
        return {"poisoned": False, "poisoned_items": [], "clean_context": []}

    poisoned_items = []
    clean_context = []

    for item in context:
        item_type = item.get("type", "")
        content = item.get("content", {})

        if item_type == "tool_definition":
            result = scan_tool_definition(content)
        elif item_type == "tool_response":
            result = scan_tool_response(content)
        else:
            result = {"poisoned": False, "blocked": 0, "triggered": [], "clean": content}

        clean_item = dict(item)
        clean_item["content"] = result.get("clean_tool") or result.get("clean") or content
        clean_context.append(clean_item)

        if result["poisoned"]:
            poisoned_items.append({
                "type": item_type,
                "triggered": result["triggered"],
            })

    return {
        "poisoned": len(poisoned_items) > 0,
        "poisoned_items": poisoned_items,
        "clean_context": clean_context,
    }

# -------------------------------------------------------
# Helper: scan text against a list of patterns
# -------------------------------------------------------
def _scan_text(text: str, patterns: list) -> tuple:
    blocked = 0
    triggered = []
    s = text

    for pattern in patterns:
        new_s = pattern.sub("[BLOCKED]", s)
        if new_s != s:
            blocked += 1
            triggered.append(pattern.pattern)
            s = new_s

    return s, blocked, triggered