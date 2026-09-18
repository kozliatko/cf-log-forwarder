"""Unit tests for cf_poller.py (pure functions + state + emitters)."""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import cf_poller as cp


# =====================================================================
# cef_escape
# =====================================================================
class TestCefEscape:
    def test_plain(self):
        assert cp.cef_escape("plain") == "plain"

    def test_equals(self):
        assert cp.cef_escape("with=equals") == "with\\=equals"

    def test_pipe(self):
        assert cp.cef_escape("pipe|here") == "pipe\\|here"

    def test_backslash(self):
        assert cp.cef_escape("back\\slash") == "back\\\\slash"

    def test_control_characters_stripped(self):
        assert cp.cef_escape("line1\nline2") == "line1 line2"
        assert cp.cef_escape("tab\there") == "tab here"
        assert cp.cef_escape("cr\rhere") == "cr here"
        assert cp.cef_escape("null\x00char") == "null char"
        assert cp.cef_escape("del\x7fchar") == "del char"

    def test_log_injection_neutralized(self):
        out = cp.cef_escape("evil\nCEF:0|fake|log")
        assert "\n" not in out
        assert out == "evil CEF:0\\|fake\\|log"

    def test_none(self):
        assert cp.cef_escape(None) == ""


# =====================================================================
# truncate_cef_payload (L1 fix)
# =====================================================================
class TestTruncateCefPayload:
    def test_short_payload_unchanged(self):
        assert cp.truncate_cef_payload("a=1 b=2") == "a=1 b=2"

    def test_long_payload_truncated_to_limit(self):
        payload = " ".join(f"k{i}={i}" for i in range(500))
        out = cp.truncate_cef_payload(payload, 900)
        assert len(out) <= 900

    def test_no_dangling_escape_after_truncation(self):
        # value with backslashes -> truncation may split an escape sequence
        payload = " ".join(f"k{i}=v\\\\v" for i in range(200))
        out = cp.truncate_cef_payload(payload, 900)
        assert (len(out) - len(out.rstrip("\\"))) % 2 == 0

    def test_cut_on_field_boundary(self):
        # the result must not end in the middle of a key=value token
        payload = " ".join(f"k{i}={i}" for i in range(500))
        out = cp.truncate_cef_payload(payload, 900)
        # after removing the possibly incomplete last token, the last token
        # must be complete: 'key=value' without trailing partial key
        last = out.rsplit(" ", 1)[-1]
        assert "=" in last

    def test_all_fields_preserved_when_possible(self):
        # short fields: truncation at boundary keeps whole fields
        payload = " ".join(f"k{i:04d}={i}" for i in range(100))
        out = cp.truncate_cef_payload(payload, 900)
        # every remaining field must be one of the original ones
        kept = out.split(" ")
        original = set(payload.split(" "))
        assert all(f in original for f in kept)


# =====================================================================
# syslog / CEF message building
# =====================================================================
class TestCefMessage:
    def test_pri_computation(self):
        msg = cp.build_cef_message(18, "cloudflare-security",
                                   datetime(2026, 9, 18, 2, 27, 40, tzinfo=timezone.utc),
                                   "block", "Cloudflare WAF/firewall event", 7,
                                   {"src": "1.2.3.4"})
        # facility 18 * 8 + severity 2 (cef 7 -> syslog 2) = 146
        assert msg.startswith("<146>")

    def test_contains_header_and_extension(self):
        msg = cp.build_cef_message(17, "cloudflare-audit",
                                   datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc),
                                   "login", "Cloudflare audit event", 5,
                                   {"suser": "a@b.c", "rt": "123"})
        assert "CEF:0|Cloudflare|CF-Poller|1.0|login|Cloudflare audit event|5|" in msg
        assert "suser=a@b.c" in msg
        assert "rt=123" in msg
        assert "cloudflare-audit" in msg

    def test_output_respects_size_limit(self):
        big_ext = {f"cs{i}": "x" * 100 for i in range(20)}
        msg = cp.build_cef_message(16, "t",
                                   datetime.now(timezone.utc),
                                   "sig", "name", 3, big_ext)
        # payload (after the PRI+timestamp+tag prefix) is capped at 900
        payload = msg.split(": ", 1)[1]
        assert len(payload) <= 900


class TestSeverityMapping:
    def test_cef_to_syslog(self):
        assert cp.cef_sev_to_syslog(0) == 6
        assert cp.cef_sev_to_syslog(3) == 6
        assert cp.cef_sev_to_syslog(4) == 4
        assert cp.cef_sev_to_syslog(6) == 4
        assert cp.cef_sev_to_syslog(7) == 2
        assert cp.cef_sev_to_syslog(10) == 2

    def test_security_action_severities(self):
        assert cp.severity_for_security({"action": "block"}) == 7
        assert cp.severity_for_security({"action": "challenge"}) == 6
        assert cp.severity_for_security({"action": "managed_challenge"}) == 6
        assert cp.severity_for_security({"action": "allow"}) == 2
        assert cp.severity_for_security({"action": "skip"}) == 2
        assert cp.severity_for_security({"action": "log"}) == 3
        assert cp.severity_for_security({"action": "unknown_action"}) == 4


# =====================================================================
# mappers
# =====================================================================
class TestMappers:
    def test_map_dns(self):
        rec = {"datetime": "2026-09-18T05:00:25Z", "queryName": "example.com",
               "queryType": "A", "responseCode": "NOERROR",
               "protocol": "UDP", "coloName": "DFW"}
        sig, when, sev, ext, raw = cp.map_dns(rec)
        assert sig == "NOERROR"
        assert sev == 3
        assert ext["request"] == "example.com"
        assert ext["cs1Label"] == "cfQueryType"
        assert raw is rec

    def test_map_dns_error_code(self):
        rec = {"datetime": "2026-09-18T05:00:25Z", "queryName": "x.com",
               "queryType": "A", "responseCode": "SERVFAIL"}
        _, _, sev, _, _ = cp.map_dns(rec)
        assert sev == 5

    def test_map_audit(self):
        rec = {"when": "2026-09-18T10:34:14Z",
               "action": {"type": "token_create"},
               "actor": {"email": "a@b.c", "ip": "1.2.3.4", "id": "u1"},
               "resource": {"type": "account", "id": "acc1"},
               "metadata": {"token_name": "t1"}}
        sig, when, sev, ext, raw = cp.map_audit(rec)
        assert sig == "token_create"
        assert sev == 5
        assert ext["suser"] == "a@b.c"
        assert ext["src"] == "1.2.3.4"
        assert ext["cs2"] == "account:acc1"
        assert ext["cs1Label"] == "cfAction"

    def test_map_requests_severity(self):
        base = {"datetime": "2026-09-18T05:41:00Z",
                "clientRequestHTTPHost": "example.com",
                "clientRequestPath": "/x", "clientRequestQuery": ""}
        assert cp.map_requests({**base, "edgeResponseStatus": 500})[2] == 8
        assert cp.map_requests({**base, "edgeResponseStatus": 403})[2] == 5
        assert cp.map_requests({**base, "edgeResponseStatus": 200})[2] == 3
        assert cp.map_requests({**base, "edgeResponseStatus": None})[2] == 3

    def test_map_requests_uri(self):
        rec = {"datetime": "2026-09-18T05:41:00Z",
               "clientRequestHTTPHost": "example.com",
               "clientRequestPath": "/a/b", "clientRequestQuery": "?x=1"}
        _, _, _, ext, _ = cp.map_requests(rec)
        assert ext["request"] == "example.com/a/b?x=1"

    def test_map_security_uri_and_severity(self):
        rec = {"datetime": "2026-09-18T02:18:00Z", "action": "block",
               "clientRequestHTTPHost": "example.com",
               "clientRequestPath": "/s", "clientRequestQuery": "",
               "clientIP": "9.9.9.9", "source": "firewallManaged",
               "ruleId": "r1", "clientCountryName": "US",
               "clientASNDescription": "Acme", "wafAttackScoreClass": "clean",
               "userAgent": "UA" * 300}
        sig, _, sev, ext, _ = cp.map_security(rec)
        assert sig == "block" and sev == 7
        assert ext["request"] == "example.com/s"
        # user agent truncated to 200 chars
        assert len(ext["requestClientApplication"]) == 200

    def test_rt_is_epoch_millis(self):
        rec = {"datetime": "1970-01-01T00:00:01Z"}
        _, _, _, ext, _ = cp.map_dns(rec)
        assert ext["rt"] == "1000"


# =====================================================================
# state (atomic save / load)
# =====================================================================
class TestState:
    def test_roundtrip(self, tmp_path, monkeypatch):
        state_file = tmp_path / "state.json"
        monkeypatch.setattr(cp, "STATE_FILE", state_file)
        assert cp.load_state() == {}
        cp.save_state_atomic({"audit": {"last": "2026-09-18T10:00:00Z"}})
        assert cp.load_state() == {"audit": {"last": "2026-09-18T10:00:00Z"}}

    def test_atomic_save_leaves_no_temp_files(self, tmp_path, monkeypatch):
        state_file = tmp_path / "state.json"
        monkeypatch.setattr(cp, "STATE_FILE", state_file)
        cp.save_state_atomic({"a": {"last": "x"}})
        leftovers = list(tmp_path.glob(".cf_poller_state-*"))
        assert leftovers == []

    def test_state_file_permissions(self, tmp_path, monkeypatch):
        state_file = tmp_path / "state.json"
        monkeypatch.setattr(cp, "STATE_FILE", state_file)
        cp.save_state_atomic({"a": {"last": "x"}})
        assert (state_file.stat().st_mode & 0o777) == 0o600

    def test_load_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cp, "STATE_FILE", tmp_path / "nope.json")
        assert cp.load_state() == {}

    def test_load_corrupt_file(self, tmp_path, monkeypatch):
        bad = tmp_path / "state.json"
        bad.write_text("not json{", encoding="utf-8")
        monkeypatch.setattr(cp, "STATE_FILE", bad)
        assert cp.load_state() == {}

    def test_load_old_format_rejected(self, tmp_path, monkeypatch):
        old = tmp_path / "state.json"
        old.write_text(json.dumps({"audit_ids": [1, 2, 3]}), encoding="utf-8")
        monkeypatch.setattr(cp, "STATE_FILE", old)
        assert cp.load_state() == {}


# =====================================================================
# emitters
# =====================================================================
class TestEmitters:
    def test_jsonl_emitter(self, capsys):
        e = cp.JsonlEmitter(enabled=True)
        e.emit("2026-09-18T05:00:25Z", "dns", "example.com", {"a": 1})
        out = capsys.readouterr().out.strip()
        assert json.loads(out) == {"ts": "2026-09-18T05:00:25Z",
                                   "source": "dns",
                                   "zone": "example.com",
                                   "data": {"a": 1}}

    def test_jsonl_disabled(self, capsys):
        e = cp.JsonlEmitter(enabled=False)
        e.emit("t", "dns", None, {"a": 1})
        assert capsys.readouterr().out == ""
        assert e.sent == 0

    def test_syslog_sender_dry_mode(self, capsys, monkeypatch):
        monkeypatch.setattr(cp, "SYSLOG_HOST", "")
        s = cp.SyslogSender(dry_run=False)
        assert s.dry is True  # no host -> dry
        s.send("<13>test")
        assert capsys.readouterr().out.strip() == "<13>test"
        assert s.sent == 1


# =====================================================================
# time helpers
# =====================================================================
class TestTimeHelpers:
    def test_parse_iso_with_z(self):
        dt = cp.parse_iso("2026-09-18T05:41:16Z")
        assert dt.year == 2026 and dt.tzinfo is not None

    def test_parse_iso_fractional(self):
        dt = cp.parse_iso("2026-09-18T05:41:16.123Z")
        assert dt.microsecond == 123000

    def test_fmt_iso_roundtrip(self):
        s = "2026-09-18T05:41:16Z"
        assert cp.fmt_iso(cp.parse_iso(s)) == s

    def test_iso_now_format(self):
        assert cp.iso_now().endswith("Z")
        assert len(cp.iso_now()) == 20
