"""The scheduled job must run every ignored release gate to completion."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
WITNESS_MANIFEST = ROOT / "crates" / "maki-witness" / "Cargo.toml"
ETCD_GATE = ROOT / "crates" / "maki-witness" / "tests" / "etcd_ha.rs"
ETCD_CFG = '#[cfg(all(unix, feature = "etcd-qualification"))]'


class ReleaseGateContract(unittest.TestCase):
    def test_nightly_does_not_stop_at_the_first_failing_gate_binary(self):
        workflow = WORKFLOW.read_text()
        self.assertIn(
            "run: cargo test --workspace --release --locked --no-fail-fast -- --ignored\n",
            workflow,
        )

    def test_integration_gate_opt_in_requires_a_same_repository_pull_request(self):
        workflow = WORKFLOW.read_text()
        for job in ("nightly-gates", "etcd-qualification"):
            match = re.search(rf"^  {job}:\n    if: ([^\n]+)", workflow, re.MULTILINE)
            self.assertIsNotNone(match)
            for event, repository, branch, enabled in (
                ("schedule", "", "", True),
                ("workflow_dispatch", "", "", True),
                ("push", "seo-rii/maki", "review/integration-test", False),
                ("pull_request", "seo-rii/maki", "review/integration-test", True),
                ("pull_request", "external/fork", "review/integration-test", False),
                ("pull_request", "seo-rii/maki", "fix/ordinary", False),
            ):
                with self.subTest(job=job, event=event, repository=repository, branch=branch):
                    expression = match.group(1)
                    values = {
                        "github.event.pull_request.head.repo.full_name": repository,
                        "github.event_name": event,
                        "github.repository": "seo-rii/maki",
                        "github.head_ref": branch,
                    }
                    for name, value in values.items():
                        expression = expression.replace(name, repr(value))
                    expression = expression.replace("||", "or").replace("&&", "and")
                    actual = eval(expression, {"__builtins__": {}}, {
                        "startsWith": lambda value, prefix: value.startswith(prefix),
                    })
                    self.assertIs(actual, enabled)

    def test_etcd_quorum_gate_is_an_opt_in_feature(self):
        # The quorum gate refuses to skip without an operator-provided etcd
        # binary, so the unfiltered `-- --ignored` run must not compile it.
        self.assertIn("\netcd-qualification = []\n", WITNESS_MANIFEST.read_text())
        gate = ETCD_GATE.read_text()
        self.assertIn(f"{ETCD_CFG}\nmod quorum {{", gate)
        self.assertNotIn("#[cfg(unix)]\nmod quorum", gate)


if __name__ == "__main__":
    unittest.main()
