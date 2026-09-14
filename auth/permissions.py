"""
Granular per-service permission levels.

Each service has named permission levels that map to OAuth scopes. Most levels
are cumulative. A small set of least-privilege profiles is exact because those
scope combinations do not fit a linear permission hierarchy.

Usage:
    --permissions gmail:organize drive:readonly

Gmail levels: readonly, organize, drafts, send, full; exact profile: send-only
Tasks levels: readonly, manage, full
Drive, Docs, Sheets, and Slides also provide an exact file profile that uses
Google's drive.file scope instead of broad Drive access.
"""

import logging
from typing import Dict, FrozenSet, List, Optional, Tuple

from auth.scopes import (
    GMAIL_READONLY_SCOPE,
    GMAIL_LABELS_SCOPE,
    GMAIL_MODIFY_SCOPE,
    GMAIL_COMPOSE_SCOPE,
    GMAIL_SEND_SCOPE,
    GMAIL_SETTINGS_BASIC_SCOPE,
    DRIVE_READONLY_SCOPE,
    DRIVE_FILE_SCOPE,
    DRIVE_SCOPE,
    CALENDAR_READONLY_SCOPE,
    CALENDAR_EVENTS_SCOPE,
    CALENDAR_SCOPE,
    DOCS_READONLY_SCOPE,
    DOCS_WRITE_SCOPE,
    SHEETS_READONLY_SCOPE,
    SHEETS_WRITE_SCOPE,
    CHAT_READONLY_SCOPE,
    CHAT_WRITE_SCOPE,
    CHAT_SPACES_SCOPE,
    CHAT_SPACES_READONLY_SCOPE,
    FORMS_BODY_SCOPE,
    FORMS_BODY_READONLY_SCOPE,
    FORMS_RESPONSES_READONLY_SCOPE,
    SLIDES_SCOPE,
    SLIDES_READONLY_SCOPE,
    TASKS_SCOPE,
    TASKS_READONLY_SCOPE,
    CONTACTS_SCOPE,
    CONTACTS_READONLY_SCOPE,
    CUSTOM_SEARCH_SCOPE,
    SCRIPT_PROJECTS_SCOPE,
    SCRIPT_PROJECTS_READONLY_SCOPE,
    SCRIPT_DEPLOYMENTS_SCOPE,
    SCRIPT_DEPLOYMENTS_READONLY_SCOPE,
    SCRIPT_PROCESSES_READONLY_SCOPE,
    SCRIPT_METRICS_SCOPE,
)

logger = logging.getLogger(__name__)

# Ordered permission levels per service.
# Each entry is (level_name, [additional_scopes_at_this_level]).
# Scopes are CUMULATIVE: level N includes all scopes from levels 0..N.
SERVICE_PERMISSION_LEVELS: Dict[str, List[Tuple[str, List[str]]]] = {
    "gmail": [
        ("readonly", [GMAIL_READONLY_SCOPE]),
        ("organize", [GMAIL_LABELS_SCOPE, GMAIL_MODIFY_SCOPE]),
        ("drafts", [GMAIL_COMPOSE_SCOPE]),
        ("send", [GMAIL_SEND_SCOPE]),
        ("full", [GMAIL_SETTINGS_BASIC_SCOPE]),
    ],
    "drive": [
        ("readonly", [DRIVE_READONLY_SCOPE]),
        ("full", [DRIVE_SCOPE, DRIVE_FILE_SCOPE]),
    ],
    "calendar": [
        ("readonly", [CALENDAR_READONLY_SCOPE]),
        ("full", [CALENDAR_SCOPE, CALENDAR_EVENTS_SCOPE]),
    ],
    "docs": [
        ("readonly", [DOCS_READONLY_SCOPE, DRIVE_READONLY_SCOPE]),
        ("full", [DOCS_WRITE_SCOPE, DRIVE_READONLY_SCOPE, DRIVE_FILE_SCOPE]),
    ],
    "sheets": [
        ("readonly", [SHEETS_READONLY_SCOPE, DRIVE_READONLY_SCOPE]),
        ("full", [SHEETS_WRITE_SCOPE, DRIVE_READONLY_SCOPE]),
    ],
    "chat": [
        ("readonly", [CHAT_READONLY_SCOPE, CHAT_SPACES_READONLY_SCOPE]),
        ("full", [CHAT_WRITE_SCOPE, CHAT_SPACES_SCOPE]),
    ],
    "forms": [
        ("readonly", [FORMS_BODY_READONLY_SCOPE, FORMS_RESPONSES_READONLY_SCOPE]),
        ("full", [FORMS_BODY_SCOPE, FORMS_RESPONSES_READONLY_SCOPE]),
    ],
    "slides": [
        ("readonly", [SLIDES_READONLY_SCOPE]),
        ("full", [SLIDES_SCOPE]),
    ],
    "tasks": [
        ("readonly", [TASKS_READONLY_SCOPE]),
        ("manage", [TASKS_SCOPE]),
        ("full", []),
    ],
    "contacts": [
        ("readonly", [CONTACTS_READONLY_SCOPE]),
        ("full", [CONTACTS_SCOPE]),
    ],
    "search": [
        ("readonly", [CUSTOM_SEARCH_SCOPE]),
        ("full", [CUSTOM_SEARCH_SCOPE]),
    ],
    "appscript": [
        (
            "readonly",
            [
                SCRIPT_PROJECTS_READONLY_SCOPE,
                SCRIPT_DEPLOYMENTS_READONLY_SCOPE,
                SCRIPT_PROCESSES_READONLY_SCOPE,
                SCRIPT_METRICS_SCOPE,
                DRIVE_READONLY_SCOPE,
            ],
        ),
        (
            "full",
            [
                SCRIPT_PROJECTS_SCOPE,
                SCRIPT_DEPLOYMENTS_SCOPE,
                SCRIPT_PROCESSES_READONLY_SCOPE,
                SCRIPT_METRICS_SCOPE,
                DRIVE_FILE_SCOPE,
            ],
        ),
    ],
}

# Exact profiles are non-cumulative. They support least-privilege combinations
# that branch from the ordered levels above.
SERVICE_PERMISSION_PROFILES: Dict[str, Dict[str, List[str]]] = {
    "gmail": {
        "send-only": [GMAIL_SEND_SCOPE],
    },
    "drive": {
        "file": [DRIVE_FILE_SCOPE],
    },
    "docs": {
        "file": [DOCS_READONLY_SCOPE, DOCS_WRITE_SCOPE, DRIVE_FILE_SCOPE],
    },
    "sheets": {
        "file": [SHEETS_READONLY_SCOPE, SHEETS_WRITE_SCOPE, DRIVE_FILE_SCOPE],
    },
    "slides": {
        "file": [SLIDES_READONLY_SCOPE, SLIDES_SCOPE, DRIVE_FILE_SCOPE],
    },
}

# Actions denied at specific permission levels.
# Maps service -> level -> frozenset of denied action names.
# Levels not listed here (or services without entries) deny nothing.
SERVICE_DENIED_ACTIONS: Dict[str, Dict[str, FrozenSet[str]]] = {
    "tasks": {
        "manage": frozenset({"delete", "clear_completed"}),
    },
}


def is_action_denied(service: str, action: str) -> bool:
    """Check whether *action* is denied for *service* under current permissions.

    Returns ``False`` when granular permissions mode is not active, when the
    service has no permission entry, or when the configured level does not
    deny the action.
    """
    if _PERMISSIONS is None:
        return False
    level = _PERMISSIONS.get(service)
    if level is None:
        return False
    denied = SERVICE_DENIED_ACTIONS.get(service, {}).get(level, frozenset())
    return action in denied


# Module-level state: parsed --permissions config
# Dict mapping service_name -> level_name, e.g. {"gmail": "organize"}
_PERMISSIONS: Optional[Dict[str, str]] = None


def set_permissions(permissions: Optional[Dict[str, str]]) -> None:
    """Set granular permissions from parsed --permissions argument."""
    global _PERMISSIONS
    _PERMISSIONS = permissions
    if permissions is not None:
        logger.info("Granular permissions set: %s", permissions)


def get_permissions() -> Optional[Dict[str, str]]:
    """Return current permissions dict, or None if not using granular mode."""
    return _PERMISSIONS


def is_permissions_mode() -> bool:
    """Check if granular permissions mode is active."""
    return _PERMISSIONS is not None


def get_scopes_for_permission(service: str, level: str) -> List[str]:
    """
    Get cumulative scopes for a service at a given permission level.

    Returns all scopes up to and including the named level.
    Raises ValueError if service or level is unknown.
    """
    levels = SERVICE_PERMISSION_LEVELS.get(service)
    if levels is None:
        raise ValueError(f"Unknown service: '{service}'")

    exact_scopes = SERVICE_PERMISSION_PROFILES.get(service, {}).get(level)
    if exact_scopes is not None:
        return sorted(set(exact_scopes))

    cumulative: List[str] = []
    found = False
    for level_name, level_scopes in levels:
        cumulative.extend(level_scopes)
        if level_name == level:
            found = True
            break

    if not found:
        valid = [name for name, _ in levels]
        raise ValueError(
            f"Unknown permission level '{level}' for service '{service}'. "
            f"Valid levels: {valid}"
        )

    return sorted(set(cumulative))


def get_all_permission_scopes() -> List[str]:
    """
    Get the combined scopes for all services at their configured permission levels.

    Only meaningful when is_permissions_mode() is True.
    """
    if _PERMISSIONS is None:
        return []

    all_scopes: set = set()
    for service, level in _PERMISSIONS.items():
        all_scopes.update(get_scopes_for_permission(service, level))
    return list(all_scopes)


def get_allowed_scopes_set() -> Optional[set]:
    """
    Get the set of allowed scopes under permissions mode (for tool filtering).

    Returns None if permissions mode is not active.
    """
    if _PERMISSIONS is None:
        return None
    return set(get_all_permission_scopes())


def has_allowed_tool_scopes(required_scopes) -> bool:
    """Check tool scopes against the configured permission profile.

    The drive.file scope permits Drive API reads only for files available to
    the app. Treat it as sufficient for read tools while retaining that file
    access boundary.
    """
    allowed_scopes = get_allowed_scopes_set()
    if allowed_scopes is None:
        return True

    return all(
        scope in allowed_scopes
        or (scope == DRIVE_READONLY_SCOPE and DRIVE_FILE_SCOPE in allowed_scopes)
        for scope in required_scopes
    )


def get_valid_levels(service: str) -> List[str]:
    """Get valid permission level names for a service."""
    levels = SERVICE_PERMISSION_LEVELS.get(service)
    if levels is None:
        return []
    ordered_levels = [name for name, _ in levels]
    exact_profiles = list(SERVICE_PERMISSION_PROFILES.get(service, {}))
    return ordered_levels + exact_profiles


def parse_permissions_arg(permissions_list: List[str]) -> Dict[str, str]:
    """
    Parse --permissions arguments like ["gmail:organize", "drive:full"].

    Returns dict mapping service -> level.
    Raises ValueError on parse errors (unknown service, invalid level, bad format).
    """
    result: Dict[str, str] = {}
    for entry in permissions_list:
        if ":" not in entry:
            raise ValueError(
                f"Invalid permission format: '{entry}'. "
                f"Expected 'service:level' (e.g., 'gmail:organize', 'drive:readonly')"
            )
        service, level = entry.split(":", 1)
        if service in result:
            raise ValueError(f"Duplicate service in permissions: '{service}'")
        if service not in SERVICE_PERMISSION_LEVELS:
            raise ValueError(
                f"Unknown service: '{service}'. "
                f"Valid services: {sorted(SERVICE_PERMISSION_LEVELS.keys())}"
            )
        valid = get_valid_levels(service)
        if level not in valid:
            raise ValueError(
                f"Unknown level '{level}' for service '{service}'. "
                f"Valid levels: {valid}"
            )
        result[service] = level
    return result
