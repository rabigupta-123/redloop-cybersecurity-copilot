"""Unit tests for TargetResolver handle and username extraction (Phase J.1).

Covers:
1. Quoted handles ('handle', "handle", `handle`).
2. Unquoted handles (handle).
3. @-prefixed handles (@handle).
4. Platform-prefixed handles ('on GitHub: handle', 'Twitter: @handle', 'Reddit: handle', etc.).
5. Natural language prompts with handles and OSINT context.
"""
import pytest
from redloop.assessment.context_resolver import TargetResolver
from redloop.assessment.orchestrator import TaskOrchestrator


# ==============================================================================
# 1. TargetResolver.classify_target Handle Formats (>=15 tests)
# ==============================================================================

@pytest.mark.parametrize("input_target,expected_handle", [
    # Quoted
    ("'shadow_broker'", "shadow_broker"),
    ('"cipher_wolf"', "cipher_wolf"),
    ("`binary_phantom`", "binary_phantom"),
    ("  'dark_spectre_99'  ", "dark_spectre_99"),
    # Unquoted
    ("shadow_coder_v2", "shadow_coder_v2"),
    ("null_root_42", "null_root_42"),
    ("stealth_hacker_7", "stealth_hacker_7"),
    ("iron_sentinel_01", "iron_sentinel_01"),
    # @-prefixed
    ("@quantum_sec_dev", "quantum_sec_dev"),
    ("@kernel_panic_9", "kernel_panic_9"),
    ("  @silent_observer_33  ", "silent_observer_33"),
    # Platform-prefixed
    ("on GitHub: shadow_broker", "shadow_broker"),
    ("GitHub: shadow_coder", "shadow_coder"),
    ("on Twitter: @stealth_fox", "stealth_fox"),
    ("Twitter: cyber_sentinel", "cyber_sentinel"),
    ("Reddit: red_team_lead", "red_team_lead"),
    ("handle: ghost_writer_01", "ghost_writer_01"),
    ("username: apex_predator", "apex_predator"),
    ("Keybase: sec_researcher", "sec_researcher"),
])
def test_target_resolver_classify_target_handles(input_target: str, expected_handle: str):
    t_type, cleaned = TargetResolver.classify_target(input_target)
    assert t_type == "username", f"Failed to classify '{input_target}' as username (got {t_type})"
    assert cleaned == expected_handle, f"Expected cleaned handle '{expected_handle}', got '{cleaned}'"


# ==============================================================================
# 2. TargetResolver.extract_prompt_target from Natural Language Prompts
# ==============================================================================

@pytest.mark.parametrize("prompt,expected_handle", [
    ("Search public forums and social platforms for accounts using username 'dark_spectre_99'.", "dark_spectre_99"),
    ("Investigate online footprint and code repositories belonging to user handle 'shadow_coder_v2'.", "shadow_coder_v2"),
    ("Can you check if handle 'binary_phantom' is registered across Github, Reddit, and Twitter?", "binary_phantom"),
    ("Perform an OSINT search for username 'cipher_wolf_88' to locate active profiles.", "cipher_wolf_88"),
    ("Look up discussion board posts and open-source contributions by nickname 'null_root_42'.", "null_root_42"),
    ("Find online presence and alias associations for operator 'stealth_hacker_7'.", "stealth_hacker_7"),
    ("Query developer platforms and paste sites for activity under username 'quantum_sec_dev'.", "quantum_sec_dev"),
    ("Check social networks and gaming forums for profiles matching username 'iron_sentinel_01'.", "iron_sentinel_01"),
    ("Search for public accounts and forum threads authored by alias 'byte_bandit_x'.", "byte_bandit_x"),
    ("Conduct username reconnaissance across digital communities for handle 'apex_predator_net'.", "apex_predator_net"),
    ("Investigate commit history and profile details for open-source username 'kernel_panic_9'.", "kernel_panic_9"),
    ("Discover accounts and public profiles associated with user nickname 'silent_observer_33'.", "silent_observer_33"),
    ("Can you run reconnaissance on GitHub: apex_sec_researcher?", "apex_sec_researcher"),
    ("Find all digital traces for @cyber_phantom_x across developer communities.", "cyber_phantom_x"),
    ("Lookup footprint for username: ghost_operator_55 on public repositories.", "ghost_operator_55"),
])
def test_target_resolver_extract_prompt_target_handles(prompt: str, expected_handle: str):
    target, t_type = TargetResolver.extract_prompt_target(prompt)
    assert t_type == "username", f"Failed for '{prompt}': got type '{t_type}'"
    assert target == expected_handle, f"Failed for '{prompt}': expected '{expected_handle}', got '{target}'"


# ==============================================================================
# 3. End-to-End Orchestrator Parsing
# ==============================================================================

def test_orchestrator_parses_quoted_username_without_clarification():
    orch = TaskOrchestrator()
    prompt = "Search public forums and social platforms for accounts using username 'dark_spectre_99'."
    res = orch.parse_intent(prompt)
    assert res.get("intent") == "OSINT_USERNAME"
    assert res.get("action") == "osint_username"
    assert res.get("target") == "dark_spectre_99"
    assert res.get("target_type") == "username"
