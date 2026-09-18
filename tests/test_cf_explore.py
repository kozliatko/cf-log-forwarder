"""Unit tests for cf_explore.py (pure helpers)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import cf_explore as ce


class TestParseEnvFile:
    def test_basic(self, tmp_path):
        f = tmp_path / ".env"
        f.write_text("A=1\nB=two\n", encoding="utf-8")
        assert ce.parse_env_file(f) == {"A": "1", "B": "two"}

    def test_hash_without_space_kept(self, tmp_path):
        f = tmp_path / ".env"
        f.write_text("A=token#withhash\n", encoding="utf-8")
        assert ce.parse_env_file(f)["A"] == "token#withhash"

    def test_inline_comment_with_space(self, tmp_path):
        f = tmp_path / ".env"
        f.write_text("A=value # note\n", encoding="utf-8")
        assert ce.parse_env_file(f)["A"] == "value"

    def test_quoted_hash_kept(self, tmp_path):
        f = tmp_path / ".env"
        f.write_text('A="hash # inside"\n', encoding="utf-8")
        assert ce.parse_env_file(f)["A"] == "hash # inside"

    def test_comments_and_blanks_skipped(self, tmp_path):
        f = tmp_path / ".env"
        f.write_text("# comment\n\n  # indented comment\nA=1\n", encoding="utf-8")
        assert ce.parse_env_file(f) == {"A": "1"}

    def test_missing_file(self, tmp_path):
        assert ce.parse_env_file(tmp_path / "nope.env") == {}


class TestFmtVal:
    def test_none(self):
        assert ce.fmt_val(None) == ""

    def test_list(self):
        assert ce.fmt_val([1, 2]) == "1,2"

    def test_bool(self):
        assert ce.fmt_val(True) == "yes"
        assert ce.fmt_val(False) == "no"

    def test_str(self):
        assert ce.fmt_val("x") == "x"
        assert ce.fmt_val(403) == "403"


class TestColumns:
    def test_all_datasets_have_columns(self):
        for ds in ("security", "requests", "dns"):
            cols = ce.GRAPHQL_DATASETS[ds]["columns"]
            assert len(cols) > 0
            assert all(len(c) == 3 for c in cols)

    def test_audit_columns(self):
        assert any(h == "ACTION" for _, h, _ in ce.AUDIT_COLUMNS)

    def test_datasets_registry_complete(self):
        assert set(ce.GRAPHQL_DATASETS) == {"security", "requests", "dns"}
