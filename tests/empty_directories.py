#!/usr/bin/env python3
"""Public recovery path-set tests; no private encoder or tuning implementation."""
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
import unicodedata
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("directory_reader", ROOT / "recovery_reference.py")
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


class EmptyDirectories(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="crate-empty-directories-")
        self.work = pathlib.Path(self.temp.name)
        self.src, self.dst = self.work / "source", self.work / "restored"
        (self.src / ".crate").mkdir(parents=True)
        self.manifest = {"crate_manifest_version": "3.0", "files": []}

    def tearDown(self):
        reader.cleanup_scratch()
        self.temp.cleanup()

    def recover(self, private=False):
        (self.src / ".crate" / "manifest.json").write_text(json.dumps(self.manifest))
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
                reader, "publication_needs_private_tree", return_value=private):
            return reader.main(self.src, self.dst)

    def file(self, name="song", corrupt=False):
        (self.src / "payload").write_bytes(b"audio bytes")
        self.manifest["files"].append({"original_path": name, "encoded_path": "payload",
            "codec_used": "none", "original_bytes": 11,
            "sha256_original": hashlib.sha256(b"wrong bytes" if corrupt else b"audio bytes").hexdigest()})

    def test_legacy_empty_directories(self):
        self.manifest["empty_dirs"] = ["empty", "nested/also empty"]
        self.file()
        self.assertEqual(self.recover(), 0)
        self.assertEqual({str(p.relative_to(self.dst)) for p in self.dst.rglob("*")},
                         {"empty", "nested", "nested/also empty", "song"})
        self.assertEqual((self.dst / "song").read_bytes(), b"audio bytes")

    def test_dirs_and_empty_dirs_share_names_and_root(self):
        self.manifest["dirs"] = [{"path": ""}, {"path": "parent"}, {"path": "parent/empty"}]
        self.manifest["empty_dirs"] = ["parent/empty"]
        self.assertEqual(self.recover(private=True), 0)
        self.assertTrue((self.dst / "parent/empty").is_dir())
        self.assertEqual(list(self.work.glob(".crate-recovery-tree-*")), [])

    def test_directory_metadata_is_not_replayed(self):
        self.manifest["dirs"] = [{"path": "empty", "fs_meta": {"mode": 0},
                                  "xattr_sha256": "not-interpreted-by-public-reader"}]
        self.assertEqual(self.recover(), 0)
        self.assertNotEqual((self.dst / "empty").stat().st_mode & 0o777, 0)

    def test_malicious_paths_refuse_before_private_publication(self):
        for path in ("../outside", "/outside", "a/../../outside", "bad\u0000path"):
            with self.subTest(path=path):
                self.manifest["empty_dirs"] = ["safe", path]
                with self.assertRaises(reader.Refused):
                    self.recover(private=True)
                self.assertFalse(self.dst.exists())
                self.assertFalse((self.work / "outside").exists())

    def test_invalid_directory_shapes_refuse(self):
        for value in (None, "empty", [None], [""], [7], ["a", "a"]):
            with self.subTest(value=value):
                self.manifest["empty_dirs"] = value
                with self.assertRaises(reader.Refused):
                    self.recover(private=True)
                self.assertFalse(self.dst.exists())

    def test_invalid_dirs_rows_refuse(self):
        for value in (None, "empty", ["empty"], [{}], [{"path": None}],
                      [{"path": "a/./b"}], [{"path": "a/"}]):
            with self.subTest(value=value):
                self.manifest["dirs"] = value
                with self.assertRaises(reader.Refused):
                    self.recover(private=True)
                self.assertFalse(self.dst.exists())

    def test_empty_directory_aliases_follow_destination_rules(self):
        probe = self.work / "CASE"
        probe.mkdir()
        case_insensitive = (self.work / "case").exists()
        probe.rmdir()
        self.manifest["empty_dirs"] = ["Album", "album"]
        if case_insensitive:
            with self.assertRaises(reader.Refused):
                self.recover(private=True)
            self.assertFalse(self.dst.exists())
        else:
            self.assertEqual(self.recover(private=True), 0)
            self.assertEqual({p.name for p in self.dst.iterdir()}, {"Album", "album"})

    def test_existing_case_alias_refuses_without_writing_below_it(self):
        self.dst.mkdir()
        existing = self.dst / "ALBUM"
        existing.mkdir()
        if not (self.dst / "album").exists():
            self.skipTest("destination filesystem is case-sensitive")
        (existing / "owner-file").write_bytes(b"owner data")
        self.manifest["empty_dirs"] = ["a_new", "album/empty"]
        with self.assertRaises(reader.Refused):
            self.recover()
        self.assertEqual({p.name for p in self.dst.iterdir()}, {"ALBUM"})
        self.assertEqual({p.name for p in existing.iterdir()}, {"owner-file"})
        self.assertEqual((existing / "owner-file").read_bytes(), b"owner data")

    def test_existing_unicode_alias_refuses_without_writing_below_it(self):
        self.dst.mkdir()
        (self.dst / "caf\u00e9").mkdir()
        stored = next(self.dst.iterdir())
        requested = unicodedata.normalize("NFD", stored.name)
        if requested == stored.name:
            requested = unicodedata.normalize("NFC", stored.name)
        if requested == stored.name or not (self.dst / requested).exists():
            self.skipTest("destination filesystem does not alias these Unicode names")
        self.manifest["empty_dirs"] = [requested + "/empty"]
        with self.assertRaises(reader.Refused):
            self.recover()
        self.assertEqual(list(stored.iterdir()), [])

    def test_injected_existing_case_alias_refuses_before_writing(self):
        self.dst.mkdir()
        existing = self.dst / "ALBUM"
        existing.mkdir()
        (existing / "owner-file").write_bytes(b"owner data")
        self.manifest["empty_dirs"] = ["a_new", "album/empty"]
        requested = self.dst / "album"
        real_lstat = pathlib.Path.lstat

        def aliased_lstat(path, *args, **kwargs):
            if path == requested:
                return real_lstat(existing, *args, **kwargs)
            return real_lstat(path, *args, **kwargs)

        with mock.patch.object(pathlib.Path, "lstat", aliased_lstat):
            with self.assertRaisesRegex(reader.Refused, "spelling aliases an existing name"):
                self.recover()
        self.assertEqual({p.name for p in self.dst.iterdir()}, {"ALBUM"})
        self.assertEqual((existing / "owner-file").read_bytes(), b"owner data")

    def test_injected_existing_unicode_alias_refuses_before_writing(self):
        self.dst.mkdir()
        existing = self.dst / "caf\u00e9"
        existing.mkdir()
        self.manifest["empty_dirs"] = ["a_new", "cafe\u0301/empty"]
        requested = self.dst / "cafe\u0301"
        real_lstat = pathlib.Path.lstat

        def aliased_lstat(path, *args, **kwargs):
            if path == requested:
                return real_lstat(existing, *args, **kwargs)
            return real_lstat(path, *args, **kwargs)

        with mock.patch.object(pathlib.Path, "lstat", aliased_lstat):
            with self.assertRaisesRegex(reader.Refused, "spelling aliases an existing name"):
                self.recover()
        self.assertEqual({p.name for p in self.dst.iterdir()}, {"caf\u00e9"})
        self.assertEqual(list(existing.iterdir()), [])

    def test_existing_exact_spelling_parent_accepts_new_empty_directory(self):
        self.dst.mkdir()
        existing = self.dst / "album"
        existing.mkdir()
        (existing / "owner-file").write_bytes(b"owner data")
        self.manifest["empty_dirs"] = ["album/empty", "album/second"]
        self.assertEqual(self.recover(), 0)
        self.assertEqual({p.name for p in existing.iterdir()}, {"owner-file", "empty", "second"})
        self.assertEqual((existing / "owner-file").read_bytes(), b"owner data")

    def test_existing_empty_directory_metadata_is_preserved(self):
        self.dst.mkdir()
        folder = self.dst / "empty"
        folder.mkdir(mode=0o700)
        before = folder.stat()
        self.manifest["dirs"] = [{"path": "empty", "fs_meta": {"mode": 0o777}}]
        self.assertEqual(self.recover(), 0)
        after = folder.stat()
        self.assertEqual((before.st_ino, before.st_mode, before.st_mtime_ns),
                         (after.st_ino, after.st_mode, after.st_mtime_ns))

    def test_later_occupied_directory_refuses_without_new_output(self):
        self.dst.mkdir()
        (self.dst / "z_conflict").write_bytes(b"owner data")
        self.manifest["empty_dirs"] = ["a_new", "z_conflict"]
        with self.assertRaises(reader.Refused):
            self.recover()
        self.assertEqual({p.name for p in self.dst.iterdir()}, {"z_conflict"})
        self.assertEqual((self.dst / "z_conflict").read_bytes(), b"owner data")

    def test_new_directories_created_after_successful_preflight(self):
        self.dst.mkdir()
        self.manifest["empty_dirs"] = ["a_new/deeper", "z_new"]
        self.assertEqual(self.recover(), 0)
        self.assertEqual({str(p.relative_to(self.dst)) for p in self.dst.rglob("*")},
                         {"a_new", "a_new/deeper", "z_new"})

    def test_file_directory_collision_refuses(self):
        self.file("taken")
        self.manifest["empty_dirs"] = ["taken"]
        with self.assertRaises(reader.Refused):
            self.recover(private=True)
        self.assertFalse(self.dst.exists())

    def test_directory_symlink_collision_refuses(self):
        self.manifest["empty_dirs"] = ["link/empty"]
        self.manifest["symlinks"] = [{"path": "link", "target": "../outside"}]
        with self.assertRaises(reader.Refused):
            self.recover(private=True)
        self.assertFalse(self.dst.exists())

    def test_existing_symlink_parent_is_not_followed(self):
        outside = self.work / "outside"
        outside.mkdir()
        self.dst.mkdir()
        (self.dst / "link").symlink_to(outside, target_is_directory=True)
        self.manifest["empty_dirs"] = ["link/empty"]
        with self.assertRaises(reader.Refused):
            self.recover()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue((self.dst / "link").is_symlink())

    def test_existing_file_is_preserved(self):
        self.dst.mkdir()
        (self.dst / "empty").write_bytes(b"owner data")
        self.manifest["empty_dirs"] = ["empty"]
        with self.assertRaises(reader.Refused):
            self.recover()
        self.assertEqual((self.dst / "empty").read_bytes(), b"owner data")

    def test_occupied_output_file_is_reported_as_partial_salvage(self):
        self.dst.mkdir()
        (self.dst / "occupied").write_bytes(b"owner data")
        self.file("occupied")
        self.manifest["empty_dirs"] = ["a_new"]
        self.assertEqual(self.recover(), 1)
        self.assertEqual((self.dst / "occupied").read_bytes(), b"owner data")
        self.assertTrue((self.dst / "a_new").is_dir())
        self.assertFalse((self.dst / "occupied.UNVERIFIED").exists())

    def test_corrupt_file_is_quarantined_with_empty_dirs(self):
        self.file(corrupt=True)
        self.manifest["empty_dirs"] = ["empty"]
        self.assertEqual(self.recover(private=True), 1)
        self.assertTrue((self.dst / "empty").is_dir())
        self.assertFalse((self.dst / "song").exists())
        self.assertEqual((self.dst / "song.UNVERIFIED").read_bytes(), b"audio bytes")


if __name__ == "__main__":
    unittest.main(verbosity=2)
