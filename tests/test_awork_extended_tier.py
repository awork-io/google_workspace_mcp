"""Tests for the curated Extended tool tier used by awork's AI agent."""

from core.tool_tier_loader import ToolTierLoader


def test_extended_excludes_account_and_sharing_administration_tools():
    loader = ToolTierLoader()
    services = ["gmail", "drive", "calendar", "docs", "sheets", "slides"]

    extended_tools = set(loader.get_tools_up_to_tier("extended", services))

    assert len(extended_tools) == 53
    assert extended_tools.isdisjoint(
        {
            "list_gmail_filters",
            "manage_gmail_filter",
            "manage_drive_access",
            "set_drive_file_permissions",
        }
    )


def test_complete_keeps_account_and_sharing_administration_tools():
    loader = ToolTierLoader()

    complete_tools = set(loader.get_tools_up_to_tier("complete", ["gmail", "drive"]))

    assert {
        "list_gmail_filters",
        "manage_gmail_filter",
        "manage_drive_access",
        "set_drive_file_permissions",
    } <= complete_tools
