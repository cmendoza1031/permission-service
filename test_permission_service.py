import pytest

from permission_service import PermissionService

NOW = 1000


@pytest.fixture
def svc():
    return PermissionService()


# ---- Part 1: basic roles, assignment, check ----

def test_assigned_role_grants_permission(svc):
    svc.create_role("viewer", {"read"})
    svc.assign_role("alice", "viewer")
    assert svc.check("alice", "read", NOW) is True


def test_permission_not_in_role_is_denied(svc):
    svc.create_role("viewer", {"read"})
    svc.assign_role("alice", "viewer")
    assert svc.check("alice", "write", NOW) is False


def test_unknown_user_is_denied(svc):
    svc.create_role("viewer", {"read"})
    assert svc.check("nobody", "read", NOW) is False


def test_unknown_permission_is_denied(svc):
    svc.create_role("viewer", {"read"})
    svc.assign_role("alice", "viewer")
    assert svc.check("alice", "does-not-exist", NOW) is False


def test_user_with_multiple_roles_gets_union(svc):
    svc.create_role("viewer", {"read"})
    svc.create_role("billing", {"invoice"})
    svc.assign_role("alice", "viewer")
    svc.assign_role("alice", "billing")
    assert svc.check("alice", "read", NOW) is True
    assert svc.check("alice", "invoice", NOW) is True


def test_role_with_no_permissions_denies(svc):
    svc.create_role("empty", set())
    svc.assign_role("alice", "empty")
    assert svc.check("alice", "read", NOW) is False


def test_duplicate_role_rejected(svc):
    svc.create_role("viewer", {"read"})
    with pytest.raises(ValueError):
        svc.create_role("viewer", {"write"})


def test_assign_unknown_role_rejected(svc):
    with pytest.raises(ValueError):
        svc.assign_role("alice", "ghost")


def test_roles_are_not_shared_between_users(svc):
    svc.create_role("viewer", {"read"})
    svc.assign_role("alice", "viewer")
    assert svc.check("bob", "read", NOW) is False


# ---- Part 2: inheritance ----

def test_child_inherits_parent_permissions(svc):
    svc.create_role("viewer", {"read"})
    svc.create_role("editor", {"write"}, parent="viewer")
    svc.assign_role("alice", "editor")
    assert svc.check("alice", "write", NOW) is True
    assert svc.check("alice", "read", NOW) is True


def test_grandchild_inherits_through_chain(svc):
    svc.create_role("viewer", {"read"})
    svc.create_role("editor", {"write"}, parent="viewer")
    svc.create_role("admin", {"delete"}, parent="editor")
    svc.assign_role("alice", "admin")
    assert svc.check("alice", "read", NOW) is True
    assert svc.check("alice", "write", NOW) is True
    assert svc.check("alice", "delete", NOW) is True


def test_parent_does_not_inherit_child_permissions(svc):
    svc.create_role("viewer", {"read"})
    svc.create_role("editor", {"write"}, parent="viewer")
    svc.assign_role("bob", "viewer")
    assert svc.check("bob", "write", NOW) is False


def test_unknown_parent_rejected(svc):
    with pytest.raises(ValueError):
        svc.create_role("editor", {"write"}, parent="ghost")
    assert "editor" not in svc.roles


def test_child_with_no_own_permissions_still_inherits(svc):
    svc.create_role("viewer", {"read"})
    svc.create_role("intern", set(), parent="viewer")
    svc.assign_role("alice", "intern")
    assert svc.check("alice", "read", NOW) is True
    assert svc.check("alice", "write", NOW) is False


def test_parent_permission_change_propagates_to_child(svc):
    svc.create_role("viewer", {"read"})
    svc.create_role("editor", {"write"}, parent="viewer")
    svc.assign_role("alice", "editor")
    assert svc.check("alice", "comment", NOW) is False
    svc.roles["viewer"]["permissions"].add("comment")
    assert svc.check("alice", "comment", NOW) is True


def test_unrelated_branches_do_not_leak(svc):
    svc.create_role("viewer", {"read"})
    svc.create_role("editor", {"write"}, parent="viewer")
    svc.create_role("auditor", {"audit"}, parent="viewer")
    svc.assign_role("alice", "editor")
    assert svc.check("alice", "audit", NOW) is False


# ---- Part 3: expiry and revoke ----

def test_valid_before_expiry(svc):
    svc.create_role("viewer", {"read"})
    svc.assign_role("alice", "viewer", expires_at=2000)
    assert svc.check("alice", "read", 1999) is True


def test_denied_exactly_at_expiry(svc):
    svc.create_role("viewer", {"read"})
    svc.assign_role("alice", "viewer", expires_at=2000)
    assert svc.check("alice", "read", 2000) is False


def test_denied_after_expiry(svc):
    svc.create_role("viewer", {"read"})
    svc.assign_role("alice", "viewer", expires_at=2000)
    assert svc.check("alice", "read", 3000) is False


def test_no_expiry_never_expires(svc):
    svc.create_role("viewer", {"read"})
    svc.assign_role("alice", "viewer")
    assert svc.check("alice", "read", 10**12) is True


def test_expired_assignment_blocks_inherited_permissions_too(svc):
    svc.create_role("viewer", {"read"})
    svc.create_role("editor", {"write"}, parent="viewer")
    svc.assign_role("alice", "editor", expires_at=2000)
    assert svc.check("alice", "read", 2000) is False
    assert svc.check("alice", "write", 2000) is False


def test_revoke_is_immediate(svc):
    svc.create_role("viewer", {"read"})
    svc.assign_role("alice", "viewer")
    assert svc.check("alice", "read", NOW) is True
    svc.revoke_role("alice", "viewer")
    assert svc.check("alice", "read", NOW) is False


def test_revoke_unassigned_or_unknown_is_noop(svc):
    svc.create_role("viewer", {"read"})
    svc.revoke_role("nobody", "viewer")
    svc.assign_role("alice", "viewer")
    svc.revoke_role("alice", "ghost")
    assert svc.check("alice", "read", NOW) is True


def test_revoke_one_role_keeps_the_other(svc):
    svc.create_role("viewer", {"read"})
    svc.create_role("billing", {"invoice"})
    svc.assign_role("alice", "viewer")
    svc.assign_role("alice", "billing")
    svc.revoke_role("alice", "viewer")
    assert svc.check("alice", "read", NOW) is False
    assert svc.check("alice", "invoice", NOW) is True


def test_expired_role_does_not_block_other_valid_role(svc):
    svc.create_role("viewer", {"read"})
    svc.create_role("billing", {"invoice"})
    svc.assign_role("alice", "viewer", expires_at=2000)
    svc.assign_role("alice", "billing")
    assert svc.check("alice", "read", 2500) is False
    assert svc.check("alice", "invoice", 2500) is True


def test_same_permission_from_expired_and_valid_role_is_allowed(svc):
    svc.create_role("a", {"read"})
    svc.create_role("b", {"read"})
    svc.assign_role("alice", "a", expires_at=2000)
    svc.assign_role("alice", "b")
    assert svc.check("alice", "read", 2500) is True


def test_reassign_after_revoke_works(svc):
    svc.create_role("viewer", {"read"})
    svc.assign_role("alice", "viewer")
    svc.revoke_role("alice", "viewer")
    svc.assign_role("alice", "viewer")
    assert svc.check("alice", "read", NOW) is True


def test_reassign_overwrites_expiry(svc):
    svc.create_role("viewer", {"read"})
    svc.assign_role("alice", "viewer", expires_at=2000)
    assert svc.check("alice", "read", 2500) is False
    svc.assign_role("alice", "viewer", expires_at=5000)
    assert svc.check("alice", "read", 2500) is True


# ---- Final: decision logging ----

def test_check_logs_allow_with_granting_role(svc, caplog):
    svc.create_role("viewer", {"read"})
    svc.create_role("editor", {"write"}, parent="viewer")
    svc.assign_role("alice", "editor")
    with caplog.at_level("INFO", logger="permission_service"):
        svc.check("alice", "read", NOW)
    assert "allowed=True" in caplog.text
    assert "granted_by=viewer" in caplog.text


def test_check_logs_denial(svc, caplog):
    with caplog.at_level("INFO", logger="permission_service"):
        svc.check("nobody", "read", NOW)
    assert "allowed=False" in caplog.text
    assert "granted_by=None" in caplog.text
