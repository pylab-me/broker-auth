from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest
import urllib.parse
from contextlib import redirect_stderr
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "broker_auth.py"
SPEC = importlib.util.spec_from_file_location("broker_auth", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
broker_auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(broker_auth)


class BrokerAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="broker-auth-test-")
        self.addCleanup(temporary.cleanup)
        self.output_path = Path(temporary.name) / "outputs"
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.responses: dict[str, dict[str, str] | SystemExit] = {}
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.enterContext(redirect_stdout(self.stdout))
        self.enterContext(redirect_stderr(self.stderr))
        self.enterContext(
            mock.patch.dict(
                os.environ,
                {
                    "BROKER_URL": "https://broker.example",
                    "PROJECT": "source-project",
                    "SOURCE_REPOSITORY": "org/source",
                    "GIT_REF": "refs/heads/main",
                    "WORKFLOW_NAME": "build",
                    "RUN_ID": "42",
                    "ACTOR": "builder",
                    "COMMIT_SHA": "test-sha",
                    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://runtime.example/oidc",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "FAKE_RUNTIME_TOKEN",
                    "PROBE_HEALTHZ": "false",
                    "GITHUB_OUTPUT": str(self.output_path),
                },
                clear=True,
            )
        )
        self.enterContext(mock.patch.object(broker_auth, "http_request", side_effect=self.fake_http_request))

    def fake_http_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
        expected_status: int | None = 200,
    ) -> tuple[int, dict[str, str], bytes]:
        payload = json.loads(body) if body else {}
        self.requests.append((method, url, payload))
        path = urllib.parse.urlsplit(url).path
        if path == "/oidc":
            response = {"value": "FAKE_OIDC_TOKEN"}
        elif path == "/v1/ci/exchange":
            response = {"session_id": "FAKE_SHARED_SESSION"}
        elif path == "/v1/grants/repo-read":
            repository = payload["target_repo"]
            response = self.responses.get(
                repository,
                {
                    "grant_id": "grant-" + repository,
                    "repo": repository,
                    "token": "FAKE_TOKEN_" + repository.replace("/", "_"),
                    "expires_at": "2030-01-01T00:00:00Z",
                },
            )
            if isinstance(response, SystemExit):
                raise response
        else:
            self.fail(f"Unexpected HTTP request: {method} {url}")
        return 200, {}, json.dumps(response).encode("utf-8")

    def outputs(self) -> dict[str, str]:
        if not self.output_path.exists():
            return {}
        return dict(line.split("=", 1) for line in self.output_path.read_text(encoding="utf-8").splitlines())

    def grant_payloads(self) -> list[dict[str, str]]:
        return [
            payload for _, url, payload in self.requests if urllib.parse.urlsplit(url).path == "/v1/grants/repo-read"
        ]

    def test_multiple_repositories_exchange_once_and_share_session(self) -> None:
        os.environ["TARGET_REPO"] = " org/buildkit\r\norg/sdk,org/buildkit, "
        self.assertEqual(broker_auth.main(), 0)
        paths = [urllib.parse.urlsplit(url).path for _, url, _ in self.requests]
        self.assertEqual(paths.count("/oidc"), 1)
        self.assertEqual(paths.count("/v1/ci/exchange"), 1)
        payloads = self.grant_payloads()
        self.assertEqual([p["target_repo"] for p in payloads], ["org/buildkit", "org/sdk"])
        self.assertEqual({p["session_id"] for p in payloads}, {"FAKE_SHARED_SESSION"})
        self.assertEqual({p["project"] for p in payloads}, {"source-project"})
        outputs = self.outputs()
        grants = json.loads(outputs["repo_read_grants_json"])
        self.assertEqual(set(grants), {"org/buildkit", "org/sdk"})
        for repository, grant in grants.items():
            self.assertEqual(grant["repo"], repository)
            self.assertIn("::add-mask::" + grant["token"], self.stdout.getvalue())
        self.assertNotIn('"token"', self.stdout.getvalue())
        for field in ("grant_id", "repo", "token", "expires_at"):
            self.assertEqual(outputs[field], "")

    def test_existing_session_skips_oidc_and_exchange(self) -> None:
        os.environ["BROKER_SESSION_ID"] = "FAKE_EXISTING_SESSION"
        os.environ["TARGET_REPO"] = "org/buildkit\norg/sdk"
        del os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
        del os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
        self.assertEqual(broker_auth.main(), 0)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(
            {p["session_id"] for p in self.grant_payloads()},
            {"FAKE_EXISTING_SESSION"},
        )
        self.assertEqual(self.outputs()["session_id"], "FAKE_EXISTING_SESSION")

    def test_single_repository_populates_scalar_and_json_outputs(self) -> None:
        os.environ["TARGET_REPO"] = "org/buildkit"
        self.assertEqual(broker_auth.main(), 0)
        outputs = self.outputs()
        grant = json.loads(outputs["repo_read_grants_json"])["org/buildkit"]
        for field in ("grant_id", "repo", "token", "expires_at"):
            self.assertEqual(outputs[field], grant[field])

    def test_no_targets_exchanges_session_without_requesting_grants(self) -> None:
        self.assertEqual(broker_auth.main(), 0)
        self.assertEqual(self.grant_payloads(), [])
        self.assertEqual(self.outputs()["repo_read_grants_json"], "{}")
        self.assertEqual(self.outputs()["token"], "")

    def test_failure_stops_batch_without_publishing_partial_credentials(self) -> None:
        os.environ["TARGET_REPO"] = "org/buildkit\norg/denied\norg/unused"
        self.responses["org/denied"] = SystemExit(1)
        with self.assertRaises(SystemExit):
            broker_auth.main()
        self.assertEqual(
            [p["target_repo"] for p in self.grant_payloads()],
            ["org/buildkit", "org/denied"],
        )
        self.assertNotIn("repo_read_grants_json", self.outputs())
        self.assertNotIn("token", self.outputs())
        self.assertIn("org/denied", self.stderr.getvalue())

    def test_invalid_targets_fail_before_any_network_request(self) -> None:
        for value in ("org/repo,not-a-repo", "org/..", "org/repo/extra", ",,"):
            with self.subTest(value=value):
                os.environ["TARGET_REPO"] = value
                with self.assertRaises(SystemExit):
                    broker_auth.main()
                self.assertEqual(self.requests, [])

    def test_reused_session_failure_does_not_fall_back_to_exchange(self) -> None:
        os.environ["BROKER_SESSION_ID"] = "FAKE_EXPIRED_SESSION"
        os.environ["TARGET_REPO"] = "org/buildkit"
        self.responses["org/buildkit"] = SystemExit(1)
        with self.assertRaises(SystemExit):
            broker_auth.main()
        self.assertEqual(len(self.requests), 1)
        self.assertNotIn("repo_read_grants_json", self.outputs())

    def test_malformed_grants_are_rejected_without_output(self) -> None:
        for changes in (
            {"repo": "org/other"},
            {"grant_id": ""},
            {"expires_at": ""},
            {"token": "FAKE_TOKEN\ninjected=value"},
        ):
            with self.subTest(changes=changes):
                self.responses["org/buildkit"] = {
                    "repo": "org/buildkit",
                    "grant_id": "test-grant",
                    "token": "FAKE_TOKEN",
                    "expires_at": "2030-01-01T00:00:00Z",
                    **changes,
                }
                with self.assertRaises(SystemExit):
                    broker_auth.request_repo_read("https://broker.example", {}, "FAKE_SESSION", "org/buildkit")
                self.assertEqual(self.outputs(), {})


if __name__ == "__main__":
    unittest.main()
