# Specs for this problem
## problem instructions
Imagine you're building the access-control service for an internal tool. Admins define roles, each role grants a set of permissions, and users are assigned roles. Other services call yours to ask one question: 'Is this user allowed to do this?'

Some roles build on others. For example, an Editor can do everything a Viewer can, plus more. And some access is temporary, like a contractor who should lose access after 30 days.

Before you write any code, walk us through your design:

What data structures would you use for users, roles, and permissions?
How would you answer 'can this user do X?' quickly, including through role inheritance?
What edge cases would you test for?
How would you debug and ship it?

## Design:
## Clarifying questions → assumptions
- One parent per role? → yes (a tree, not a graph)
- Expiry per user or per role assignment? → per assignment
- Who can call the admin methods? → assume authenticated admins; out of scope
- In-memory, `now` passed in → yes

## Data structures
roles: dict[role -> {permissions: set[str], parent: str | None}]
assignments: dict[user -> dict[role -> expires_at | None]]

## How check is fast
For each unexpired role the user has, walk role -> parent -> parent, return True on the first role whose set contains the permission. Cost: roles per user x depth, both small.
Tradeoff: walk vs flatten (table above). Walking keeps one source of truth; cache later if needed.
Cycles: a parent must already exist when a role is created and can't be changed, so cycles can't form.

## Interface
create_role(name, permissions, parent=None)
assign_role(user, role, expires_at=None)
revoke_role(user, role)
check(user, permission, now) -> bool    # deny by default

## Edge cases
Deny by default (unknown user/role/permission), expired at exact boundary, revoke is immediate, unknown parent rejected, parent changes propagate to child, role with no permissions.

## Debug & ship
Failing test before every fix. Log every decision (user, permission, allowed, which role granted it) so "why was I denied?" is answerable. Roll out in shadow mode: run alongside the old system, compare decisions, then switch.

## Plan (40 min)
Part 1 (by min 15): create_role, assign_role, check, no inheritance or expiry, with tests.
Part 2 (by min 27): inheritance + cycle rule, with tests.
Part 3 (by min 35): expiry + revoke, with tests.
Last: full test run, summary.