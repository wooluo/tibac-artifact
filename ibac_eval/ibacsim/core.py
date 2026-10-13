"""Core data model: actions, authorization contracts (TAC), effects, decisions.

Design notes
------------
- Every action is a canonical string resource id, e.g. "file:/docs/project/a.md",
  "db:reports", "email:to=boss@corp.com", "net:host=api.partner.example".
  TAC scope patterns are fnmatch patterns over a (op, resource) pair, e.g.
  "db:r:reports" (read of table reports) or "file:/docs/project/**".
  Embedding the critical parameter (recipient, host, path, table) inside the
  resource id is what makes parameter-level granularity cheap to enforce.
- `ActionSpec.unauthorized` is the scenario author's ground truth: the action
  is outside the *user's intent* for the task. It is authored together with
  the TAC and cross-checked at startup (see scenarios.selfcheck()).
- Model-side stochastic choices (injection adoption, retries, NL compliance)
  are drawn from RNG streams keyed by (trial_seed, kind, spec_id) so that the
  same choice point always yields the same draw regardless of which control
  plane configuration is running. This is the internal-validity invariant:
  differences across B0-B4 are attributable to the control plane only.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from typing import Optional

TRUSTED = "trusted"
UNTRUSTED = "untrusted"

# ops vocabulary
OPS = {"read", "write", "delete", "send", "get", "exec", "spawn", "mem_w", "mem_r", "perm"}


class Verdict(Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


def rng_for(seed: int, kind: str, key: str) -> random.Random:
    """Deterministic RNG stream keyed by seed+kind+key (path-independent)."""
    return random.Random(f"{seed}|{kind}|{key}")


@dataclass
class Content:
    """A piece of text entering the agent's context, with provenance."""
    text: str
    trust: str = TRUSTED
    source: str = "system"
    instruction_tag: Optional[str] = None  # set when content embeds an injected instruction


@dataclass
class ActionSpec:
    """Auth-relevant template of one action, authored by the scenario."""
    id: str
    tool: str
    op: str
    resource: str
    params: dict = field(default_factory=dict)
    justification: str = ""
    effect_class: str = "read"          # read|write|egress|exec|spawn|perm|memory
    sensitive: bool = False             # touches credentials / sensitive personal data
    loud: bool = False                  # carries detector-visible malicious signals
    unauthorized: bool = False          # ground truth: outside user intent
    adopt_tag: Optional[str] = None     # member of an injected playbook (tainted)


@dataclass
class Action:
    """Runtime instance of an ActionSpec issued by some actor."""
    spec: ActionSpec
    actor: str
    parent: Optional[str]
    step: int
    tick: int
    tainted: bool = False
    taint_source: Optional[str] = None

    @property
    def id(self) -> str:
        return self.spec.id

    @property
    def unauthorized(self) -> bool:
        return self.spec.unauthorized


@dataclass
class Effect:
    """An actual world side effect (or sensitive read) that happened."""
    tick: int
    actor: str
    action_id: str
    kind: str                # read|write|egress|exec|spawn|perm|memory
    resource: str
    unauthorized: bool
    severe: bool             # write/egress/exec/perm, or read of sensitive data
    details: str = ""


@dataclass
class ToolResult:
    content: Optional[Content] = None
    effects: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)


@dataclass
class TAC:
    """Task Authorization Contract (intent-derived, scenario-authored)."""
    task_id: str
    scopes: list = field(default_factory=list)      # e.g. ["file:/docs/project/**", "db:r:reports"]
    ops: set = field(default_factory=lambda: set(OPS))
    tools: set = field(default_factory=set)          # pinned tool identities
    email_sinks: list = field(default_factory=list)  # approved recipients
    net_hosts: list = field(default_factory=list)    # approved egress hosts
    risky_ops: set = field(default_factory=lambda: {"delete", "perm"})
    budget: int = 40
    delegation: Optional[dict] = None                # {"scopes": [...], "tools": {...}, "email_sinks": [...]}

    def __post_init__(self):
        # derive sink allowlists from scope patterns when not set explicitly,
        # so that e.g. "net:intranet.corp" also approves GETs to that host
        if not self.net_hosts:
            self.net_hosts = [p[4:] for p in self.scopes if p.startswith("net:")]
        if not self.email_sinks:
            self.email_sinks = [p[6:] for p in self.scopes if p.startswith("email:")]

    def matches(self, op: str, resource: str) -> bool:
        for pat in self.scopes:
            kind, _, rest = pat.partition(":")
            if kind == "db":
                # "db:r:reports" / "db:w:*"
                acc, _, obj = rest.partition(":")
                want = "r" if op in ("read", "get") else "w"
                if acc != want:
                    continue
                if fnmatch(resource, f"db:{obj}"):
                    return True
            elif kind == "file":
                # optional ":ro" suffix marks a read-only file scope; strip it
                # before matching or it would pollute the glob pattern itself
                if pat.endswith(":ro"):
                    pat_eff, writable = pat[:-3], False
                else:
                    pat_eff, writable = pat, True
                if op in ("read", "list"):
                    # a directory itself is in scope when any child is
                    if fnmatch(resource, pat_eff) or fnmatch(resource + "/", pat_eff):
                        return True
                elif writable and fnmatch(resource, pat_eff):
                    return True
            elif kind == "email":
                if op == "send" and fnmatch(resource.replace("email:to=", "email:"), pat):
                    return True
            elif kind == "net":
                if op == "get" and fnmatch(resource.replace("net:host=", "net:"), pat):
                    return True
            elif kind in ("exec", "mem", "cred", "legacy", "agent"):
                if fnmatch(resource, pat):
                    return True
        return False


@dataclass
class Decision:
    verdict: Verdict
    reason: str = ""
    violation_denied: bool = False   # denied/escalated-denied a ground-truth violation
    check_us: float = 0.0            # wall-clock cost of adjudication
