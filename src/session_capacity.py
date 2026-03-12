#!/usr/bin/env python3
"""
Compute per-session hidden-data capacity summaries for Trilobyte-style
thumbnail-based communication experiments.

This script is intended to support the measurement logic behind Table III:
  - hidden data per state
  - max states per hour
  - hidden data per session
  - optional throughput conversions

It does not attempt to reproduce platform interaction or gameplay. Instead, it
provides a transparent aggregation layer over per-game capacity inputs.

Supported input modes:
  1. CSV mode:
       Read a CSV with per-game measurements and compute derived metrics.
  2. CLI mode:
       Compute metrics for a single game from command-line arguments.

Expected CSV columns:
    game,hidden_data_per_state,max_states_per_hour

Optional CSV columns:
    accounts_investigated
    session_hours
    notes

Units:
  - hidden_data_per_state is interpreted as bytes by default.
  - session duration defaults to 1 hour unless overridden.

Examples:

1) Batch mode from CSV
    python src/session_capacity.py `
      --input-csv examples/sample_results/session_capacity_input.csv `
      --out-csv examples/sample_results/session_capacity_output.csv

2) Single-game mode
    python src/session_capacity.py `
      --game "Baldur's Gate 3" `
      --hidden-data-per-state 506880 `
      --max-states-per-hour 11

3) CSV mode with kibibyte input interpretation
    python src/session_capacity.py `
      --input-csv examples/sample_results/session_capacity_input.csv `
      --unit kib

Notes:
  - If your table values are reported in KB but actually represent KiB-style
    binary units, use --unit kib.
  - Throughput is reported both in bytes/s and kbps (decimal kilobits/s).
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


@dataclass
class CapacityRow:
    game: str
    hidden_data_per_state_bytes: int
    max_states_per_hour: float
    session_hours: float = 1.0
    accounts_investigated: str = ""
    notes: str = ""


@dataclass
class CapacityResult:
    game: str
    hidden_data_per_state_bytes: int
    hidden_data_per_state_kib: float
    hidden_data_per_state_kb: float
    max_states_per_hour: float
    session_hours: float
    hidden_data_per_session_bytes: int
    hidden_data_per_session_kib: float
    hidden_data_per_session_kb: float
    hidden_data_per_session_mib: float
    hidden_data_per_session_mb: float
    bytes_per_second: float
    kbps_decimal: float
    accounts_investigated: str = ""
    notes: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute per-session capacity summaries for Trilobyte thumbnail experiments."
    )

    # Batch mode
    parser.add_argument(
        "--input-csv",
        type=Path,
        help="CSV containing per-game measurements.",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        help="Optional output CSV path for derived metrics.",
    )

    # Single-row CLI mode
    parser.add_argument("--game", type=str, help="Game name for single-game mode.")
    parser.add_argument(
        "--hidden-data-per-state",
        type=float,
        help="Per-state hidden data capacity, interpreted using --unit.",
    )
    parser.add_argument(
        "--max-states-per-hour",
        type=float,
        help="Maximum states created in one hour.",
    )
    parser.add_argument(
        "--session-hours",
        type=float,
        default=1.0,
        help="Session duration in hours. Default: 1.0",
    )
    parser.add_argument(
        "--accounts-investigated",
        type=str,
        default="",
        help="Optional metadata for single-game mode.",
    )
    parser.add_argument(
        "--notes",
        type=str,
        default="",
        help="Optional notes for single-game mode.",
    )

    parser.add_argument(
        "--unit",
        choices=["bytes", "kb", "kib"],
        default="bytes",
        help=(
            "Interpretation of hidden-data-per-state input. "
            "'kb' = 1000 bytes, 'kib' = 1024 bytes."
        ),
    )
    parser.add_argument(
        "--round-bytes",
        action="store_true",
        help="Round per-state interpreted bytes to nearest integer. Recommended for non-byte units.",
    )

    return parser.parse_args()


def convert_to_bytes(value: float, unit: str) -> int:
    if unit == "bytes":
        return int(round(value))
    if unit == "kb":
        return int(round(value * 1000))
    if unit == "kib":
        return int(round(value * 1024))
    raise ValueError(f"Unsupported unit: {unit}")


def bytes_to_kib(value: int) -> float:
    return value / 1024.0


def bytes_to_kb(value: int) -> float:
    return value / 1000.0


def bytes_to_mib(value: int) -> float:
    return value / (1024.0 * 1024.0)


def bytes_to_mb(value: int) -> float:
    return value / 1_000_000.0


def compute_result(row: CapacityRow) -> CapacityResult:
    session_bytes = int(round(row.hidden_data_per_state_bytes * row.max_states_per_hour * row.session_hours))
    seconds = row.session_hours * 3600.0
    bytes_per_second = session_bytes / seconds if seconds > 0 else 0.0
    kbps_decimal = (session_bytes * 8.0) / (row.session_hours * 3600.0 * 1000.0) if row.session_hours > 0 else 0.0

    return CapacityResult(
        game=row.game,
        hidden_data_per_state_bytes=row.hidden_data_per_state_bytes,
        hidden_data_per_state_kib=bytes_to_kib(row.hidden_data_per_state_bytes),
        hidden_data_per_state_kb=bytes_to_kb(row.hidden_data_per_state_bytes),
        max_states_per_hour=row.max_states_per_hour,
        session_hours=row.session_hours,
        hidden_data_per_session_bytes=session_bytes,
        hidden_data_per_session_kib=bytes_to_kib(session_bytes),
        hidden_data_per_session_kb=bytes_to_kb(session_bytes),
        hidden_data_per_session_mib=bytes_to_mib(session_bytes),
        hidden_data_per_session_mb=bytes_to_mb(session_bytes),
        bytes_per_second=bytes_per_second,
        kbps_decimal=kbps_decimal,
        accounts_investigated=row.accounts_investigated,
        notes=row.notes,
    )


def load_rows_from_csv(path: Path, unit: str) -> list[CapacityRow]:
    if not path.exists():
        raise FileNotFoundError(f"Missing input CSV: {path}")

    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows: list[CapacityRow] = []

        required = {"game", "hidden_data_per_state", "max_states_per_hour"}
        if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
            raise ValueError(
                "Input CSV must contain columns: game, hidden_data_per_state, max_states_per_hour"
            )

        for raw in reader:
            game = raw["game"].strip()
            if not game:
                continue

            hidden_data_per_state_raw = float(raw["hidden_data_per_state"])
            hidden_data_per_state_bytes = convert_to_bytes(hidden_data_per_state_raw, unit=unit)

            max_states_per_hour = float(raw["max_states_per_hour"])
            session_hours = float(raw.get("session_hours", "") or 1.0)
            accounts_investigated = (raw.get("accounts_investigated", "") or "").strip()
            notes = (raw.get("notes", "") or "").strip()

            rows.append(
                CapacityRow(
                    game=game,
                    hidden_data_per_state_bytes=hidden_data_per_state_bytes,
                    max_states_per_hour=max_states_per_hour,
                    session_hours=session_hours,
                    accounts_investigated=accounts_investigated,
                    notes=notes,
                )
            )

    if not rows:
        raise ValueError(f"No valid rows found in input CSV: {path}")

    return rows


def write_results_csv(path: Path, results: Iterable[CapacityResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "game",
        "hidden_data_per_state_bytes",
        "hidden_data_per_state_kib",
        "hidden_data_per_state_kb",
        "max_states_per_hour",
        "session_hours",
        "hidden_data_per_session_bytes",
        "hidden_data_per_session_kib",
        "hidden_data_per_session_kb",
        "hidden_data_per_session_mib",
        "hidden_data_per_session_mb",
        "bytes_per_second",
        "kbps_decimal",
        "accounts_investigated",
        "notes",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            row = asdict(result)
            writer.writerow(row)


def print_result(result: CapacityResult) -> None:
    print(f"Game: {result.game}")
    print(f"  Hidden data per state: {result.hidden_data_per_state_bytes} bytes")
    print(f"                         {result.hidden_data_per_state_kib:.2f} KiB")
    print(f"                         {result.hidden_data_per_state_kb:.2f} KB")
    print(f"  Max states per hour:   {result.max_states_per_hour:.2f}")
    print(f"  Session hours:         {result.session_hours:.2f}")
    print(f"  Hidden data/session:   {result.hidden_data_per_session_bytes} bytes")
    print(f"                         {result.hidden_data_per_session_kib:.2f} KiB")
    print(f"                         {result.hidden_data_per_session_kb:.2f} KB")
    print(f"                         {result.hidden_data_per_session_mib:.2f} MiB")
    print(f"                         {result.hidden_data_per_session_mb:.2f} MB")
    print(f"  Throughput:            {result.bytes_per_second:.2f} bytes/s")
    print(f"                         {result.kbps_decimal:.3f} kbps")
    if result.accounts_investigated:
        print(f"  Accounts investigated: {result.accounts_investigated}")
    if result.notes:
        print(f"  Notes:                 {result.notes}")


def print_batch_summary(results: list[CapacityResult]) -> None:
    print(f"[ok] processed {len(results)} game(s)")
    for result in results:
        print(
            f"  - {result.game}: "
            f"{result.hidden_data_per_session_bytes} bytes/session "
            f"({result.hidden_data_per_session_mb:.3f} MB, {result.kbps_decimal:.3f} kbps)"
        )


def main() -> int:
    args = parse_args()

    # Batch CSV mode
    if args.input_csv:
        rows = load_rows_from_csv(args.input_csv, unit=args.unit)
        results = [compute_result(row) for row in rows]

        print_batch_summary(results)

        if args.out_csv:
            write_results_csv(args.out_csv, results)
            print(f"[ok] wrote derived metrics to: {args.out_csv}")

        return 0

    # Single-game CLI mode
    missing = []
    if not args.game:
        missing.append("--game")
    if args.hidden_data_per_state is None:
        missing.append("--hidden-data-per-state")
    if args.max_states_per_hour is None:
        missing.append("--max-states-per-hour")

    if missing:
        raise SystemExit(
            "Either provide --input-csv, or use single-game mode with: "
            + ", ".join(missing)
        )

    row = CapacityRow(
        game=args.game,
        hidden_data_per_state_bytes=convert_to_bytes(args.hidden_data_per_state, unit=args.unit),
        max_states_per_hour=args.max_states_per_hour,
        session_hours=args.session_hours,
        accounts_investigated=args.accounts_investigated,
        notes=args.notes,
    )
    result = compute_result(row)
    print_result(result)

    if args.out_csv:
        write_results_csv(args.out_csv, [result])
        print(f"[ok] wrote derived metrics to: {args.out_csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())