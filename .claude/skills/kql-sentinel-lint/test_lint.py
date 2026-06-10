#!/usr/bin/env python3
"""
Unit tests for lint.py and validate.py.

Run from this directory:
  python3 -m unittest test_lint -v
"""

import json
import os
import unittest
from pathlib import Path
from unittest import mock

import lint
import validate

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text())


def lint_rule(rule):
    props = rule.get("properties", {})
    kql = props.get("query", "")
    findings = []
    findings += lint.check_kql_syntax(kql)
    findings += lint.check_table_references(kql)
    findings += lint.check_time_filter(kql)
    findings += lint.check_join_kind(kql)
    findings += lint.check_house_style(kql)
    findings += lint.check_semantic(kql, props)
    findings += lint.check_risks(kql)
    findings += lint.check_arm_template(rule)
    return findings


def codes(findings):
    return {f.code for f in findings}


class TestResolveLetBindings(unittest.TestCase):
    def test_multiple_lets(self):
        kql = "let lookback = ago(1h);\nlet threshold = 5;\nlet ratio = 0.75;\nSecurityEvent"
        bindings = lint.resolve_let_bindings(kql)
        self.assertEqual(bindings, {"threshold": 5.0, "ratio": 0.75})

    def test_non_numeric_lets_ignored(self):
        kql = 'let name = "admin";\nlet lookback = ago(1h);\nlet t = 3;'
        self.assertEqual(lint.resolve_let_bindings(kql), {"t": 3.0})


class TestThresholdCheck(unittest.TestCase):
    def test_literal_threshold_fires(self):
        kql = "SecurityEvent\n| summarize c = count() by AccountName\n| where c > 5"
        findings = lint.check_semantic(kql, {"triggerThreshold": 0})
        self.assertIn("S.THRESHOLD_WRONG", codes(findings))

    def test_let_resolved_threshold_fires(self):
        kql = ("let threshold = 5;\nSecurityEvent\n"
               "| summarize failures = count() by AccountName\n| where failures > threshold")
        findings = lint.check_semantic(kql, {"triggerThreshold": 0})
        self.assertIn("S.THRESHOLD_WRONG", codes(findings))

    def test_unresolved_identifier_does_not_fire(self):
        kql = ("SecurityEvent\n| summarize failures = count() by AccountName\n"
               "| where failures > unknownVar")
        findings = lint.check_semantic(kql, {"triggerThreshold": 0})
        self.assertNotIn("S.THRESHOLD_WRONG", codes(findings))

    def test_nonzero_trigger_threshold_does_not_fire(self):
        kql = ("let threshold = 5;\nSecurityEvent\n"
               "| summarize failures = count() by AccountName\n| where failures > threshold")
        findings = lint.check_semantic(kql, {"triggerThreshold": 5})
        self.assertNotIn("S.THRESHOLD_WRONG", codes(findings))


class TestFixtures(unittest.TestCase):
    def test_good_rule_has_no_errors(self):
        findings = lint_rule(load_fixture("good-rule.json"))
        errors = [f for f in findings if f.severity == "E"]
        self.assertEqual(errors, [], [f.message for f in errors])

    def test_bad_threshold_let_caught(self):
        findings = lint_rule(load_fixture("bad-threshold-let.json"))
        self.assertIn("S.THRESHOLD_WRONG", codes(findings))

    def test_bad_table_caught(self):
        findings = lint_rule(load_fixture("bad-table.json"))
        found = codes(findings)
        self.assertIn("E.TABLE_NOT_EXIST", found)
        self.assertIn("E.JOIN_WRONG_KIND", found)
        self.assertIn("C.TACTICS_INVALID", found)
        self.assertIn("C.QUERY_FREQ_FORMAT", found)


class TestValidatePrerequisites(unittest.TestCase):
    def test_skips_without_az(self):
        with mock.patch.object(validate.shutil, "which", return_value=None):
            reason = validate.check_prerequisites()
        self.assertIn("az CLI not found", reason)

    def test_skips_without_workspace(self):
        with mock.patch.object(validate.shutil, "which", return_value="/usr/bin/az"), \
             mock.patch.dict(os.environ, {validate.ENV_VAR: ""}, clear=False), \
             mock.patch.object(validate, "CONFIG_FILE", Path("/nonexistent/config.json")):
            reason = validate.check_prerequisites()
        self.assertIn("no workspace configured", reason)

    def test_run_live_returns_skipped(self):
        with mock.patch.object(validate, "check_prerequisites", return_value="az CLI not found on PATH"):
            result = validate.run_live(FIXTURES / "good-rule.json")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["findings"], [])


class TestClassifyError(unittest.TestCase):
    def test_syntax_error(self):
        finding, transient = validate.classify_error(
            "BadArgumentError: Syntax error: Query could not be parsed at 'wher'")
        self.assertIsNone(transient)
        self.assertEqual(finding["code"], "E.KQL_LIVE_SYNTAX")

    def test_semantic_error(self):
        finding, transient = validate.classify_error(
            "BadArgumentError: Failed to resolve table or column expression named 'SecurityEvents'")
        self.assertIsNone(transient)
        self.assertEqual(finding["code"], "E.KQL_LIVE_SEMANTIC")
        self.assertIn("TARGET workspace", finding["message"])

    def test_throttling_is_transient(self):
        finding, transient = validate.classify_error(
            "Response status 429: request throttled, retry after 30s")
        self.assertIsNone(finding)
        self.assertIn("throttling", transient)


if __name__ == "__main__":
    unittest.main()
