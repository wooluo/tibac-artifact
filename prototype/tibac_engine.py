"""TIBAC reference policy engine (PDP) + enforcement hook (PEP).

A dependency-free reference implementation of the authorization core described
in the paper: HMAC-signed short-lived capability tokens carrying the task
contract (scopes, sinks, budget, expiry), parameter-level scope matching,
sink allowlists, taint policy on outbound flow, delegation attenuation
(C_child = C_parent ∩ C_delegated), and a revocation list.

This is the piece a real agent framework would call in its tool-invocation
hook (LangGraph/LangChain interceptor, MCP proxy, or an OWASP-ACS-style
Guardian). Run `python3 prototype/tibac_engine.py` for the self-test.
"""
from __future__ import annotations

from fnmatch import fnmatch
import hmac
import hashlib
import json
import time
from dataclasses import dataclass, field


class PolicyDenied(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class Action:
    actor: str
    tool: str
    op: str                      # read|write|delete|send|get|exec|spawn|...
    resource: str                # "file:/docs/project/x.md", "email:to=b@corp.com"
    params: dict = field(default_factory=dict)
    tainted: bool = False        # derived from untrusted content (taint tracker)


@dataclass
class Decision:
    allow: bool
    escalate: bool = False
    reason: str = ""


def _canon(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class CapabilityToken:
    __slots__ = ("payload", "mac")

    def __init__(self, payload: dict, mac: bytes):
        self.payload = payload
        self.mac = mac

    @property
    def task(self):
        return self.payload["task"]

    @property
    def actor(self):
        return self.payload["actor"]


class PolicyDecisionPoint:
    """Issues and verifies task-bound capabilities. One instance per session."""

    def __init__(self, session_key: bytes | None = None, clock=time.time):
        self.key = session_key or hashlib.sha256(b"tibac-demo-session-key").digest()
        self.clock = clock
        self.revoked: set[str] = set()          # revoked token nonces
        self.budget_used: dict[str, int] = {}   # nonce -> consumed actions

    # ------------------------------------------------------------- issuance
    def issue(self, task_id: str, actor: str, scopes: list[str],
              email_sinks: list[str] | None = None, net_hosts: list[str] | None = None,
              ttl_s: float = 600.0, budget: int = 100,
              delegation: dict | None = None, nonce: str | None = None) -> CapabilityToken:
        payload = {
            "task": task_id, "actor": actor, "scopes": sorted(scopes),
            "sinks": sorted(email_sinks or []), "hosts": sorted(net_hosts or []),
            "delegation": delegation or None,
            "iat": self.clock(), "exp": self.clock() + ttl_s,
            "budget": budget, "nonce": nonce or f"{task_id}:{actor}:{self.clock():f}",
        }
        mac = hmac.new(self.key, _canon(payload), hashlib.sha256).digest()
        return CapabilityToken(payload, mac)

    def issue_delegated(self, parent: CapabilityToken, child_actor: str,
                        requested_scopes: list[str]) -> CapabilityToken:
        """Attenuated child token: scopes = parent ∩ delegation allowance."""
        d = parent.payload.get("delegation") or {}
        allowed = set(d.get("scopes", []))
        granted = [s for s in requested_scopes if s in allowed]
        if len(granted) != len(requested_scopes):
            raise PolicyDenied("ibac: delegation exceeds contract (attenuation)")
        return self.issue(
            task_id=f"{parent.task}/{child_actor}", actor=child_actor,
            scopes=granted,
            email_sinks=[s for s in (d.get("email_sinks") or [])
                         if s in parent.payload["sinks"]],
            net_hosts=[h for h in (d.get("net_hosts") or [])
                       if h in parent.payload["hosts"]],
            ttl_s=min(parent.payload["exp"] - self.clock(), d.get("ttl_s", 300.0)),
            budget=d.get("budget", 20), delegation=d.get("subdelegation"))

    def revoke(self, token: CapabilityToken) -> None:
        self.revoked.add(token.payload["nonce"])

    # ---------------------------------------------------------- adjudication
    def _scope_ok(self, op: str, resource: str, scopes: list[str]) -> bool:
        for pat in scopes:
            kind, _, rest = pat.partition(":")
            if kind == "db":
                acc, _, obj = rest.partition(":")
                want = "r" if op in ("read", "get") else "w"
                if acc == want and fnmatch(resource, f"db:{obj}"):
                    return True
            elif kind == "file":
                writable = not pat.endswith(":ro")
                if fnmatch(resource, pat) and (op in ("read", "list") or writable):
                    return True
            elif kind in ("email", "net", "exec", "mem", "cred", "legacy", "agent"):
                norm = resource.replace("email:to=", "email:").replace("net:host=", "net:")
                if fnmatch(norm, pat):
                    return True
        return False

    def adjudicate(self, action: Action, token: CapabilityToken) -> Decision:
        p = token.payload
        # 1 integrity
        if not hmac.compare_digest(
                token.mac, hmac.new(self.key, _canon(p), hashlib.sha256).digest()):
            return Decision(False, reason="ibac: bad token integrity")
        # 2 liveness
        if p["nonce"] in self.revoked:
            return Decision(False, reason="ibac: capability revoked")
        if self.clock() >= p["exp"]:
            return Decision(False, reason="ibac: lease expired")
        # 3 budget
        used = self.budget_used.get(p["nonce"], 0)
        if used >= p["budget"]:
            return Decision(False, reason="ibac: budget exhausted")
        # 4 scope (parameter-level: resource embeds path/table/recipient)
        if not self._scope_ok(action.op, action.resource, p["scopes"]):
            return Decision(False, reason=f"ibac: {action.resource} outside task scope")
        # 5 sink allowlists
        if action.op == "send":
            to = action.params.get("to", "")
            if to and to not in p["sinks"]:
                return Decision(False, reason="ibac: recipient not an approved sink")
        if action.op == "get":
            host = action.resource.replace("net:host=", "")
            if host not in p["hosts"]:
                return Decision(False, reason="ibac: egress host not approved")
        # 6 taint policy: outbound/sensitive actions justified by untrusted
        #   content need human confirmation
        if action.tainted and action.op in ("send", "write", "delete", "perm"):
            return Decision(False, escalate=True,
                            reason="ibac: untrusted-justified sensitive action -> escalate")
        self.budget_used[p["nonce"]] = used + 1
        return Decision(True, reason="within contract")


class EnforcementPoint:
    """PEP: wraps a tool callable with mandatory adjudication."""

    def __init__(self, pdp: PolicyDecisionPoint):
        self.pdp = pdp
        self.last_check_us: float = 0.0

    def call(self, token: CapabilityToken, action: Action, tool_fn):
        t0 = time.perf_counter_ns()
        d = self.pdp.adjudicate(action, token)
        self.last_check_us = (time.perf_counter_ns() - t0) / 1e3
        if not d.allow:
            if d.escalate:
                raise PolicyDenied(f"ESCALATE: {d.reason}")
            raise PolicyDenied(d.reason)
        return tool_fn()


# ------------------------------------------------------------------ self-test
def _selftest():
    class FakeClock:
        def __init__(self): self.t = 1_000_000.0
        def __call__(self): return self.t

    clk = FakeClock()
    pdp = PolicyDecisionPoint(clock=clk)
    tok = pdp.issue("task-1", "agent",
                    scopes=["file:/docs/project/**", "db:r:reports",
                            "email:boss@corp.com", "exec:local"],
                    email_sinks=["boss@corp.com"], ttl_s=600, budget=10,
                    delegation={"scopes": ["file:/docs/project/**"],
                                "email_sinks": [], "budget": 5})

    ok = lambda d: d.allow

    # in-scope read allowed
    a = Action("agent", "read_file", "read", "file:/docs/project/a.md")
    assert ok(pdp.adjudicate(a, tok)), "in-scope read should pass"
    # out-of-scope file denied
    a = Action("agent", "read_file", "read", "file:/root/.ssh/id_rsa")
    assert not ok(pdp.adjudicate(a, tok)), "out-of-scope read must be denied"
    # db write denied (read-only scope)
    a = Action("agent", "db_write", "write", "db:reports")
    assert not ok(pdp.adjudicate(a, tok)), "db write outside scope"
    # unapproved sink denied
    a = Action("agent", "send_email", "send", "email:to=attacker@evil.com",
               params={"to": "attacker@evil.com"})
    assert not ok(pdp.adjudicate(a, tok)), "unapproved recipient must be denied"
    # approved sink allowed; tainted same action escalates
    a = Action("agent", "send_email", "send", "email:to=boss@corp.com",
               params={"to": "boss@corp.com"})
    assert ok(pdp.adjudicate(a, tok))
    a_bad = Action("agent", "send_email", "send", "email:to=boss@corp.com",
                   params={"to": "boss@corp.com"}, tainted=True)
    d = pdp.adjudicate(a_bad, tok)
    assert not d.allow and d.escalate, "tainted outbound must escalate"
    # lease expiry
    clk.t += 601
    a = Action("agent", "read_file", "read", "file:/docs/project/a.md")
    assert "expired" in pdp.adjudicate(a, tok).reason
    clk.t -= 601
    # budget exhaustion
    for _ in range(10):
        pdp.adjudicate(Action("agent", "read_file", "read", "file:/docs/project/a.md"), tok)
    a = Action("agent", "read_file", "read", "file:/docs/project/a.md")
    assert "budget" in pdp.adjudicate(a, tok).reason
    # revocation
    tok2 = pdp.issue("task-2", "agent", scopes=["file:/tmp/**"],
                     delegation={"scopes": ["file:/tmp/**"], "budget": 5})
    pdp.revoke(tok2)
    a = Action("agent", "write_file", "write", "file:/tmp/x")
    assert "revoked" in pdp.adjudicate(a, tok2).reason
    # delegation attenuation: child request within allowance succeeds,
    # exceeding it is refused
    tok3 = pdp.issue("task-3", "agent", scopes=["file:/tmp/**"],
                     delegation={"scopes": ["file:/tmp/**"], "budget": 5})
    child = pdp.issue_delegated(tok3, "child", requested_scopes=["file:/tmp/**"])
    assert child.payload["scopes"] == ["file:/tmp/**"]
    try:
        pdp.issue_delegated(tok, "child", requested_scopes=["file:/docs/**",
                                                            "db:r:*"])
        raise AssertionError("over-broad delegation must be refused")
    except PolicyDenied as e:
        assert "attenuation" in e.reason
    child2 = pdp.issue_delegated(tok, "child2",
                                 requested_scopes=["file:/docs/project/**"])
    a = Action("child2", "read_file", "read", "file:/docs/project/a.md")
    assert ok(pdp.adjudicate(a, child2))
    a = Action("child2", "read_file", "read", "file:/docs/finance/payroll.xlsx")
    assert not ok(pdp.adjudicate(a, child2)), "child cannot exceed delegation"
    # tampered token
    tampered = CapabilityToken(dict(tok.payload), b"x" * 32)
    a = Action("agent", "read_file", "read", "file:/docs/project/a.md")
    assert "integrity" in pdp.adjudicate(a, tampered).reason

    print("tibac_engine self-test: ALL PASSED "
          "(scope/sink/taint/lease/budget/revocation/attenuation/tamper)")


if __name__ == "__main__":
    _selftest()
