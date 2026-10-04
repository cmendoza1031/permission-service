import logging

logger = logging.getLogger(__name__)


class PermissionService:
    def __init__(self):
        # role -> {"permissions": set[str], "parent": str | None}
        self.roles = {}
        # user -> {role -> expires_at | None}
        self.assignments = {}

    def create_role(self, name, permissions, parent=None):
        if name in self.roles:
            raise ValueError(f"role already exists: {name}")
        # Parent must already exist and is never changed, so cycles can't form.
        if parent is not None and parent not in self.roles:
            raise ValueError(f"unknown parent role: {parent}")
        self.roles[name] = {"permissions": set(permissions), "parent": parent}

    def assign_role(self, user, role, expires_at=None):
        if role not in self.roles:
            raise ValueError(f"unknown role: {role}")
        self.assignments.setdefault(user, {})[role] = expires_at

    def revoke_role(self, user, role):
        # No-op if the user or assignment doesn't exist.
        self.assignments.get(user, {}).pop(role, None)

    def check(self, user, permission, now):
        granted_by = self._find_granting_role(user, permission, now)
        allowed = granted_by is not None
        # Log every decision so "why was I denied?" is answerable.
        logger.info(
            "check user=%s permission=%s allowed=%s granted_by=%s",
            user, permission, allowed, granted_by,
        )
        return allowed

    def _find_granting_role(self, user, permission, now):
        """Return the role (own or inherited) that grants permission, else None."""
        for role, expires_at in self.assignments.get(user, {}).items():
            # Expired at the exact boundary: now >= expires_at.
            if expires_at is not None and now >= expires_at:
                continue
            # Walk role -> parent -> ... until some role grants the permission.
            current = role
            while current is not None:
                if permission in self.roles[current]["permissions"]:
                    return current
                current = self.roles[current]["parent"]
        return None
