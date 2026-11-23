"""F1 probe: a broken link after a container margin that ends at a literal tab must be reported."""
import pathlib, subprocess, sys, tempfile, unittest

CHECKER = pathlib.Path("/home/user/wt/audit4/scripts/check_docs_links.py")
CASES = {
    "quote-space-tab": "> \t[quoted](missing-quote.md)\n",
    "quote-two-spaces-tab": ">  \t[q2](missing-q2.md)\n",
    "bullet-continuation": "- item\n\n  \t[cont](missing-cont.md)\n",
    "ordered-continuation": "1. Step one\n\n   \tSee the [guide](missing-guide.md).\n",
}


class TabMarginProbe(unittest.TestCase):
    def test_broken_links_after_tab_margins_are_reported(self):
        for name, text in CASES.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                subprocess.run(["git", "init", "-q", str(root)], check=True)
                (root / "doc.md").write_text(text)
                subprocess.run(["git", "-C", str(root), "add", "doc.md"], check=True)
                result = subprocess.run([sys.executable, "-B", str(CHECKER), str(root)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, f"{name}: broken link not reported:\n{result.stdout}")


if __name__ == "__main__":
    unittest.main()
