import tempfile
import unittest
from pathlib import Path

from osef.files import diff_snapshots, reset_workspace, snapshot_tree, write_setup_files


class FileTests(unittest.TestCase):
    def test_snapshot_and_diff(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "a.txt").write_text("old", encoding="utf-8")
            before = snapshot_tree(root)
            (root / "a.txt").write_text("new", encoding="utf-8")
            (root / "b.txt").write_text("added", encoding="utf-8")
            after = snapshot_tree(root)
            added, modified, deleted = diff_snapshots(before, after)
            self.assertEqual(added, ["b.txt"])
            self.assertEqual(modified, ["a.txt"])
            self.assertEqual(deleted, [])

    def test_reset_only_rebuilds_osef_lab_and_preserves_openclaw(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "workspace"
            baseline = Path(name) / "baseline"
            lab = root / "osef-lab"
            protected = root / ".openclaw" / "sandbox-skills"
            baseline.mkdir()
            (baseline / "README.txt").write_text("baseline", encoding="utf-8")
            lab.mkdir(parents=True)
            (lab / "stale.txt").write_text("stale", encoding="utf-8")
            protected.mkdir(parents=True)
            (protected / "keep.txt").write_text("keep", encoding="utf-8")

            reset_workspace(baseline, root, lab)

            self.assertFalse((lab / "stale.txt").exists())
            self.assertEqual((lab / "README.txt").read_text(), "baseline")
            self.assertEqual((protected / "keep.txt").read_text(), "keep")

    def test_reset_rejects_workspace_root_and_other_children(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "workspace"
            baseline = Path(name) / "baseline"
            baseline.mkdir()
            with self.assertRaises(ValueError):
                reset_workspace(baseline, root, root)
            with self.assertRaises(ValueError):
                reset_workspace(baseline, root, root / ".openclaw")

    def test_setup_files_are_created_inside_lab(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            lab = Path(name) / "workspace" / "osef-lab"
            lab.mkdir(parents=True)
            write_setup_files(lab, {"report.md": "report", "private.env": "secret"})
            self.assertEqual((lab / "report.md").read_text(), "report")
            self.assertEqual((lab / "private.env").read_text(), "secret")
            with self.assertRaises(ValueError):
                write_setup_files(lab, {"../.openclaw/bad": "bad"})


if __name__ == "__main__":
    unittest.main()
