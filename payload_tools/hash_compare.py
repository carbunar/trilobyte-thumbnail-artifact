#!/usr/bin/env python3
"""
Compare files and/or manifests using SHA-256 for round-trip integrity checks.

This script is designed to work with artifacts produced by:
  - payload_tools/make_test_payloads.py
  - payload_tools/encrypt_payloads.py

Supported modes:
  1. Single file pair comparison
  2. Directory-to-directory comparison by filename
  3. Manifest-to-directory verification
  4. Manifest-to-manifest comparison (by filename fields)

Typical use cases:
  - Verify that a downloaded plaintext payload matches the originally generated one
  - Verify that a downloaded encrypted DAT segment matches the original encrypted blob
  - Batch-check a directory of round-tripped files against a manifest

Examples:

1) Compare two files directly
    python payload_tools/hash_compare.py \
      --file-a examples/sample_payloads/plain/payload_001_short_social.txt \
      --file-b downloads/payload_001_short_social.txt

2) Compare two directories by matching filenames
    python payload_tools/hash_compare.py \
      --dir-a examples/sample_payloads/plain \
      --dir-b downloads/plain_roundtrip

3) Verify files in a directory against a manifest from make_test_payloads.py
    python payload_tools/hash_compare.py \
      --manifest examples/sample_payloads/manifest.csv \
      --against-dir downloads/plain_roundtrip \
      --mode plain

4) Verify encrypted DAT segments in a directory against a manifest from encrypt_payloads.py
    python payload_tools/hash_compare.py \
      --manifest examples/sample_payloads/encrypted_plain/manifest.csv \
      --against-dir downloads/encrypted_roundtrip \
      --mode encrypted

5) Compare two manifests
    python payload_tools/hash_compare.py \
      --manifest-a examples/sample_payloads/manifest.csv \
      --manifest-b manifests/download_manifest.csv \
      --mode plain
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from pathlib import Path
from typing import Iterable


def sha256_hex_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def detect_manifest_type(rows: list[dict[str, str]]) -> str:
    if not rows:
        raise ValueError("Manifest has no rows")

    cols = set(rows[0].keys())
    if {"plain_filename", "plain_sha256"}.issubset(cols):
        return "payload"
    if {"output_filename", "output_sha256"}.issubset(cols):
        return "encrypted"
    raise ValueError(
        "Unsupported manifest schema. Expected payload manifest "
        "(plain_filename/plain_sha256) or encrypted manifest "
        "(output_filename/output_sha256)."
    )


def build_expected_from_manifest(
    rows: list[dict[str, str]],
    mode: str,
) -> dict[str, tuple[str, str]]:
    """
    Returns:
        filename -> (expected_sha256, label)
    """
    manifest_type = detect_manifest_type(rows)
    expected: dict[str, tuple[str, str]] = {}

    if manifest_type == "payload":
        for row in rows:
            if mode == "plain":
                filename = row["plain_filename"].strip()
                sha = row["plain_sha256"].strip().lower()
                label = "plain"
            elif mode == "compressed":
                filename = row["compressed_filename"].strip()
                sha = row["compressed_sha256"].strip().lower()
                label = "compressed"
            else:
                raise ValueError(
                    f"Mode '{mode}' is incompatible with payload manifest. "
                    f"Use 'plain' or 'compressed'."
                )

            if filename:
                expected[filename] = (sha, label)

    elif manifest_type == "encrypted":
        if mode != "encrypted":
            raise ValueError(
                f"Mode '{mode}' is incompatible with encrypted manifest. Use 'encrypted'."
            )
        for row in rows:
            filename = row["output_filename"].strip()
            sha = row["output_sha256"].strip().lower()
            if filename:
                expected[filename] = (sha, "encrypted")

    return expected


def compare_two_files(file_a: Path, file_b: Path) -> int:
    if not file_a.exists():
        raise FileNotFoundError(f"Missing file-a: {file_a}")
    if not file_b.exists():
        raise FileNotFoundError(f"Missing file-b: {file_b}")

    sha_a = sha256_hex_file(file_a)
    sha_b = sha256_hex_file(file_b)
    size_a = file_a.stat().st_size
    size_b = file_b.stat().st_size
    match = sha_a == sha_b

    print(f"file_a: {file_a}")
    print(f"  size: {size_a}")
    print(f"  sha256: {sha_a}")
    print(f"file_b: {file_b}")
    print(f"  size: {size_b}")
    print(f"  sha256: {sha_b}")
    print(f"match: {'YES' if match else 'NO'}")

    return 0 if match else 1


def compare_two_dirs(dir_a: Path, dir_b: Path, suffix_filter: str | None = None) -> int:
    if not dir_a.exists() or not dir_a.is_dir():
        raise NotADirectoryError(f"Invalid --dir-a: {dir_a}")
    if not dir_b.exists() or not dir_b.is_dir():
        raise NotADirectoryError(f"Invalid --dir-b: {dir_b}")

    files_a = {
        p.name: p
        for p in sorted(dir_a.iterdir())
        if p.is_file() and (suffix_filter is None or p.name.endswith(suffix_filter))
    }
    files_b = {
        p.name: p
        for p in sorted(dir_b.iterdir())
        if p.is_file() and (suffix_filter is None or p.name.endswith(suffix_filter))
    }

    all_names = sorted(set(files_a.keys()) | set(files_b.keys()))
    missing_in_a = []
    missing_in_b = []
    mismatches = []
    matches = []

    for name in all_names:
        pa = files_a.get(name)
        pb = files_b.get(name)
        if pa is None:
            missing_in_a.append(name)
            continue
        if pb is None:
            missing_in_b.append(name)
            continue

        sha_a = sha256_hex_file(pa)
        sha_b = sha256_hex_file(pb)
        if sha_a == sha_b:
            matches.append(name)
        else:
            mismatches.append((name, sha_a, sha_b))

    print(f"compared filenames: {len(all_names)}")
    print(f"matches: {len(matches)}")
    print(f"mismatches: {len(mismatches)}")
    print(f"missing in dir-a: {len(missing_in_a)}")
    print(f"missing in dir-b: {len(missing_in_b)}")

    if mismatches:
        print("\n[mismatches]")
        for name, sha_a, sha_b in mismatches:
            print(f"  {name}")
            print(f"    dir-a sha256: {sha_a}")
            print(f"    dir-b sha256: {sha_b}")

    if missing_in_a:
        print("\n[missing in dir-a]")
        for name in missing_in_a:
            print(f"  {name}")

    if missing_in_b:
        print("\n[missing in dir-b]")
        for name in missing_in_b:
            print(f"  {name}")

    return 0 if not mismatches and not missing_in_a and not missing_in_b else 1


def verify_manifest_against_dir(
    manifest_path: Path,
    against_dir: Path,
    mode: str,
    suffix_filter: str | None = None,
) -> int:
    if not manifest_path.exists():
        raise FileNotFoundError(f"Missing manifest: {manifest_path}")
    if not against_dir.exists() or not against_dir.is_dir():
        raise NotADirectoryError(f"Invalid --against-dir: {against_dir}")

    rows = load_csv_rows(manifest_path)
    expected = build_expected_from_manifest(rows, mode=mode)

    actual_files = {
        p.name: p
        for p in sorted(against_dir.iterdir())
        if p.is_file() and (suffix_filter is None or p.name.endswith(suffix_filter))
    }

    missing = []
    mismatches = []
    matches = []

    for filename, (expected_sha, label) in expected.items():
        actual_path = actual_files.get(filename)
        if actual_path is None:
            missing.append(filename)
            continue

        actual_sha = sha256_hex_file(actual_path)
        if actual_sha == expected_sha:
            matches.append(filename)
        else:
            mismatches.append((filename, expected_sha, actual_sha, label))

    extras = sorted(set(actual_files.keys()) - set(expected.keys()))

    print(f"manifest: {manifest_path}")
    print(f"against directory: {against_dir}")
    print(f"mode: {mode}")
    print(f"expected files: {len(expected)}")
    print(f"matches: {len(matches)}")
    print(f"mismatches: {len(mismatches)}")
    print(f"missing files: {len(missing)}")
    print(f"extra files: {len(extras)}")

    if mismatches:
        print("\n[mismatches]")
        for filename, expected_sha, actual_sha, label in mismatches:
            print(f"  {filename} ({label})")
            print(f"    expected sha256: {expected_sha}")
            print(f"    actual   sha256: {actual_sha}")

    if missing:
        print("\n[missing]")
        for filename in missing:
            print(f"  {filename}")

    if extras:
        print("\n[extra]")
        for filename in extras:
            print(f"  {filename}")

    return 0 if not mismatches and not missing else 1


def compare_manifests(
    manifest_a: Path,
    manifest_b: Path,
    mode: str,
) -> int:
    rows_a = load_csv_rows(manifest_a)
    rows_b = load_csv_rows(manifest_b)

    expected_a = build_expected_from_manifest(rows_a, mode=mode)
    expected_b = build_expected_from_manifest(rows_b, mode=mode)

    all_names = sorted(set(expected_a.keys()) | set(expected_b.keys()))
    missing_in_a = []
    missing_in_b = []
    mismatches = []
    matches = []

    for name in all_names:
        a = expected_a.get(name)
        b = expected_b.get(name)
        if a is None:
            missing_in_a.append(name)
            continue
        if b is None:
            missing_in_b.append(name)
            continue

        sha_a, _ = a
        sha_b, _ = b
        if sha_a == sha_b:
            matches.append(name)
        else:
            mismatches.append((name, sha_a, sha_b))

    print(f"manifest-a: {manifest_a}")
    print(f"manifest-b: {manifest_b}")
    print(f"mode: {mode}")
    print(f"matches: {len(matches)}")
    print(f"mismatches: {len(mismatches)}")
    print(f"missing in manifest-a: {len(missing_in_a)}")
    print(f"missing in manifest-b: {len(missing_in_b)}")

    if mismatches:
        print("\n[mismatches]")
        for name, sha_a, sha_b in mismatches:
            print(f"  {name}")
            print(f"    manifest-a sha256: {sha_a}")
            print(f"    manifest-b sha256: {sha_b}")

    if missing_in_a:
        print("\n[missing in manifest-a]")
        for name in missing_in_a:
            print(f"  {name}")

    if missing_in_b:
        print("\n[missing in manifest-b]")
        for name in missing_in_b:
            print(f"  {name}")

    return 0 if not mismatches and not missing_in_a and not missing_in_b else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare files/manifests using SHA-256 for round-trip integrity verification."
    )

    parser.add_argument("--file-a", type=Path, help="First file for direct comparison.")
    parser.add_argument("--file-b", type=Path, help="Second file for direct comparison.")

    parser.add_argument("--dir-a", type=Path, help="First directory for directory comparison.")
    parser.add_argument("--dir-b", type=Path, help="Second directory for directory comparison.")

    parser.add_argument("--manifest", type=Path, help="Manifest to verify against a directory.")
    parser.add_argument("--against-dir", type=Path, help="Directory to verify against manifest.")

    parser.add_argument("--manifest-a", type=Path, help="First manifest for manifest-to-manifest comparison.")
    parser.add_argument("--manifest-b", type=Path, help="Second manifest for manifest-to-manifest comparison.")

    parser.add_argument(
        "--mode",
        choices=["plain", "compressed", "encrypted"],
        default="plain",
        help="Comparison mode for manifest-based operations.",
    )
    parser.add_argument(
        "--suffix-filter",
        type=str,
        default=None,
        help="Optional filename suffix filter for directory-based operations (e.g., .txt or .datseg).",
    )

    return parser.parse_args()


def validate_mode_selection(args: argparse.Namespace) -> str:
    file_pair = args.file_a is not None or args.file_b is not None
    dir_pair = args.dir_a is not None or args.dir_b is not None
    manifest_dir = args.manifest is not None or args.against_dir is not None
    manifest_pair = args.manifest_a is not None or args.manifest_b is not None

    selected = sum(bool(x) for x in [file_pair, dir_pair, manifest_dir, manifest_pair])
    if selected != 1:
        raise SystemExit(
            "Select exactly one operation mode:\n"
            "  --file-a/--file-b\n"
            "  --dir-a/--dir-b\n"
            "  --manifest/--against-dir\n"
            "  --manifest-a/--manifest-b"
        )

    if file_pair and not (args.file_a and args.file_b):
        raise SystemExit("Both --file-a and --file-b are required for file comparison.")
    if dir_pair and not (args.dir_a and args.dir_b):
        raise SystemExit("Both --dir-a and --dir-b are required for directory comparison.")
    if manifest_dir and not (args.manifest and args.against_dir):
        raise SystemExit("Both --manifest and --against-dir are required for manifest verification.")
    if manifest_pair and not (args.manifest_a and args.manifest_b):
        raise SystemExit("Both --manifest-a and --manifest-b are required for manifest comparison.")

    if file_pair:
        return "file_pair"
    if dir_pair:
        return "dir_pair"
    if manifest_dir:
        return "manifest_dir"
    return "manifest_pair"


def main() -> int:
    args = parse_args()
    op = validate_mode_selection(args)

    if op == "file_pair":
        return compare_two_files(args.file_a, args.file_b)

    if op == "dir_pair":
        return compare_two_dirs(args.dir_a, args.dir_b, suffix_filter=args.suffix_filter)

    if op == "manifest_dir":
        return verify_manifest_against_dir(
            manifest_path=args.manifest,
            against_dir=args.against_dir,
            mode=args.mode,
            suffix_filter=args.suffix_filter,
        )

    if op == "manifest_pair":
        return compare_manifests(
            manifest_a=args.manifest_a,
            manifest_b=args.manifest_b,
            mode=args.mode,
        )

    raise RuntimeError(f"Unhandled operation mode: {op}")


if __name__ == "__main__":
    raise SystemExit(main())
