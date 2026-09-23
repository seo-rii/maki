"""CI must reject vulnerable or informationally unsafe Rust dependencies."""

from pathlib import Path
import unittest


WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"


class DependencyAuditContract(unittest.TestCase):
    def test_linux_ci_installs_a_pinned_auditor_and_denies_all_warnings(self):
        workflow = WORKFLOW.read_text()
        install = """      - name: install pinned RustSec auditor (Linux)
        if: runner.os == 'Linux'
        run: cargo install cargo-audit --version 0.22.1 --locked
"""
        audit = """      - name: RustSec dependency audit (Linux)
        if: runner.os == 'Linux'
        run: cargo audit --deny warnings
"""
        self.assertIn(install, workflow)
        self.assertIn(audit, workflow)
        self.assertLess(workflow.index(install), workflow.index(audit))


if __name__ == "__main__":
    unittest.main()
