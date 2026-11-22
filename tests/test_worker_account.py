from dataclasses import replace
import unittest
from unittest.mock import Mock

from edge_bridge.worker_account import (
    AccountObservation, IncludedOnlyPolicy, WorkerAccountBlocked, account_fingerprint, start_if_included,
    summarize_account,
)


class WorkerAccountTests(unittest.TestCase):
    def test_metadata_does_not_return_identity_or_infer_spending_permission(self):
        account = {"account": {"type": "chatgpt", "planType": "plus", "email": "private@example.invalid"},
                   "userId": "private-id"}
        usage = {"ordinaryUsageAllowed": True, "spendControlReached": False,
                 "rateLimits": {"credits": {"hasCredits": False, "unlimited": False}}}
        models = {"data": [{"model": "gpt-6.2-astra"}, {"model": "gpt-6.2-sol"},
                           {"model": "gpt-private-hidden", "hidden": True},
                           {"id": "private@example.invalid"}]}
        report = summarize_account(account, usage, models)
        self.assertEqual(report["models"], ["gpt-6.2-astra", "gpt-6.2-sol"])
        self.assertFalse(report["auto_reload_verified"])
        self.assertFalse(report["workers_enabled"])
        self.assertFalse(report["spend_control_reached"])
        self.assertNotIn("private", repr(report))

    def test_missing_or_ineligible_state_never_launches(self):
        fingerprint = account_fingerprint("synthetic-account", b"x" * 32)
        policy = IncludedOnlyPolicy(fingerprint, "fixture-workspace")
        good = AccountObservation("chatgpt", fingerprint, "fixture-workspace", True, 40, False, False, 10)
        denied = (
            (replace(good, authentication="api_key"), "SUBSCRIPTION_AUTH_REQUIRED"),
            (replace(good, remaining_included_percent=0), "QUOTA_EXHAUSTED"),
            (replace(good, ordinary_usage_allowed=False), "QUOTA_EXHAUSTED"),
            (replace(good, account_fingerprint="other"), "WORKER_ACCOUNT_CHANGED"),
            (replace(good, workspace_identity="other"), "WORKER_ACCOUNT_CHANGED"),
            (replace(good, workspace_identity=None), "ACCOUNT_USAGE_UNVERIFIED"),
            (replace(good, auto_reload_enabled=None), "ACCOUNT_USAGE_UNVERIFIED"),
            (replace(good, has_credits=True), "ACCOUNT_USAGE_UNVERIFIED"),
            (replace(good, observed_at=-100), "ACCOUNT_USAGE_UNVERIFIED"),
        )
        for observation, code in denied:
            with self.subTest(code=code, observation=observation):
                launch = Mock()
                with self.assertRaises(WorkerAccountBlocked) as result:
                    start_if_included(policy, lambda: observation, launch, now=11)
                self.assertEqual(result.exception.code, code)
                launch.assert_not_called()

    def test_allowed_synthetic_observation_only_calls_stub(self):
        policy = IncludedOnlyPolicy("synthetic-account", "synthetic-workspace")
        observation = AccountObservation("chatgpt", "synthetic-account", "synthetic-workspace",
                                         True, 40, False, False, 10)
        observe, launch = Mock(return_value=observation), Mock(return_value="simulation")
        self.assertEqual(start_if_included(policy, observe, launch, now=11), "simulation")
        observe.assert_called_once()
        launch.assert_called_once()

