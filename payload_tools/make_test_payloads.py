#!/usr/bin/env python3
"""
Generate reproducible benign Chinese-language plaintext payloads for
Table-I-style save-state methodology experiments.

This script creates:
  - plain UTF-8 text payloads
  - optional compressed (.zlib) variants
  - a manifest CSV describing all generated files

The payloads are intentionally benign and synthetic. They are not meant to
reproduce the original sensitive keyword corpus. Their purpose is to support a
reproducible measurement workflow:

  generate payload -> optionally transform/compress -> manually inject/upload
  -> download -> verify round-trip integrity

Example:
    python payload_tools/make_test_payloads.py \
        --outdir examples/sample_payloads \
        --count 12 \
        --compress

Output structure:
    examples/sample_payloads/
      plain/
        payload_001_short_social.txt
        payload_002_short_news.txt
        ...
      compressed/
        payload_001_short_social.txt.zlib
        ...
      manifest.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import random
import textwrap
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class PayloadSpec:
    category: str
    style: str
    text: str


# Benign Chinese placeholder content.
# These are topic-labeled, non-sensitive, and varied in length/style so they
# are useful as reproducible test payloads.
BASE_SNIPPETS: dict[str, list[str]] = {
    "social": [
        "今天和朋友一起吃晚饭，聊了旅行、电影和最近的天气，感觉很放松。",
        "周末准备去公园散步，顺便拍几张照片，晚上再整理相册。",
        "我刚刚给家里打了电话，大家都很好，计划下个月一起聚餐。",
        "下午喝了一杯咖啡，然后继续整理电脑里的旧文件和照片。",
    ],
    "news": [
        "本地社区今天举行了读书活动，很多家长和孩子一起参加，现场气氛很好。",
        "市图书馆发布了新的开放时间通知，并增加了周末亲子阅读项目。",
        "天气预报说明后两天有小雨，出门时建议携带雨具并注意路面湿滑。",
        "学校公告提醒学生下周开始办理选课，请提前确认课程安排。",
    ],
    "gaming": [
        "今天尝试了新的单机游戏存档，完成了几个支线任务，还收集了一些材料。",
        "角色升级后解锁了新的技能树，接下来准备继续探索地图边缘区域。",
        "保存进度前，我整理了背包、检查了装备，并在营地休息了一次。",
        "这个关卡的场景设计很细致，光影效果不错，值得多截几张图。",
    ],
    "travel": [
        "如果周末天气稳定，我想去海边走走，再找一家评价不错的小餐馆吃饭。",
        "这次出行计划比较简单，先订车票，再确认住宿位置和入住时间。",
        "我更喜欢白天到达目的地，这样方便熟悉路线，也更容易安排接下来的行程。",
        "旅行前最好提前备份证件照片，并把重要地址保存在手机和纸上。",
    ],
    "shopping": [
        "我比较了几家店的价格，最后还是选择了评价更稳定、售后更清楚的一家。",
        "购物清单里主要是日用品和一些零食，没有特别贵的东西。",
        "下单前我先看了评论区，确认尺寸和材质都符合预期。",
        "最近打算买一个新的移动硬盘，用来备份研究资料和照片。",
    ],
    "education": [
        "这周的任务是完成阅读笔记，并把重要概念整理成简短提纲。",
        "老师建议先理解例题，再独立完成练习，这样效率更高。",
        "我准备把课程资料按主题分类，方便之后复习和查找。",
        "下午参加了线上讨论，主要内容是项目分工和时间安排。",
    ],
}

STYLES = ("short", "medium", "long")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_text(category: str, style: str, rng: random.Random) -> str:
    snippets = BASE_SNIPPETS[category]

    if style == "short":
        chosen = rng.sample(snippets, k=1)
    elif style == "medium":
        chosen = rng.sample(snippets, k=2)
    elif style == "long":
        k = min(4, len(snippets))
        chosen = rng.sample(snippets, k=k)
    else:
        raise ValueError(f"Unsupported style: {style}")

    intro = f"【类别】{category}\n【风格】{style}\n【说明】这是用于文件注入与完整性验证的良性中文测试载荷。\n"
    body = "\n".join(chosen)
    footer = "\n【结束】该文件仅用于复现实验流程，不包含敏感内容。\n"
    return intro + body + footer


def build_payload_specs(count: int, seed: int) -> list[PayloadSpec]:
    rng = random.Random(seed)
    categories = list(BASE_SNIPPETS.keys())
    specs: list[PayloadSpec] = []

    for idx in range(count):
        category = categories[idx % len(categories)]
        style = STYLES[idx % len(STYLES)]
        text = build_text(category=category, style=style, rng=rng)
        specs.append(PayloadSpec(category=category, style=style, text=text))

    return specs


def write_plain_payload(path: Path, text: str) -> bytes:
    data = text.encode("utf-8")
    path.write_bytes(data)
    return data


def write_compressed_payload(path: Path, plain_data: bytes, level: int) -> bytes:
    compressed = zlib.compress(plain_data, level=level)
    path.write_bytes(compressed)
    return compressed


def ensure_dirs(outdir: Path, with_compressed: bool) -> tuple[Path, Path | None]:
    plain_dir = outdir / "plain"
    plain_dir.mkdir(parents=True, exist_ok=True)

    compressed_dir: Path | None = None
    if with_compressed:
        compressed_dir = outdir / "compressed"
        compressed_dir.mkdir(parents=True, exist_ok=True)

    return plain_dir, compressed_dir


def manifest_rows(
    specs: Iterable[PayloadSpec],
    plain_dir: Path,
    compressed_dir: Path | None,
    compress_level: int,
) -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []

    for idx, spec in enumerate(specs, start=1):
        stem = f"payload_{idx:03d}_{spec.style}_{spec.category}"
        plain_path = plain_dir / f"{stem}.txt"
        plain_data = write_plain_payload(plain_path, spec.text)

        row: dict[str, str | int] = {
            "payload_id": idx,
            "category": spec.category,
            "style": spec.style,
            "plain_filename": plain_path.name,
            "plain_bytes": len(plain_data),
            "plain_sha256": sha256_hex(plain_data),
            "plain_encoding": "utf-8",
            "compressed_filename": "",
            "compressed_bytes": "",
            "compressed_sha256": "",
            "compression": "",
        }

        if compressed_dir is not None:
            comp_path = compressed_dir / f"{stem}.txt.zlib"
            comp_data = write_compressed_payload(comp_path, plain_data, level=compress_level)
            row["compressed_filename"] = comp_path.name
            row["compressed_bytes"] = len(comp_data)
            row["compressed_sha256"] = sha256_hex(comp_data)
            row["compression"] = f"zlib:{compress_level}"

        rows.append(row)

    return rows


def write_manifest(outdir: Path, rows: list[dict[str, str | int]]) -> Path:
    manifest_path = outdir / "manifest.csv"
    fieldnames = [
        "payload_id",
        "category",
        "style",
        "plain_filename",
        "plain_bytes",
        "plain_sha256",
        "plain_encoding",
        "compressed_filename",
        "compressed_bytes",
        "compressed_sha256",
        "compression",
    ]
    with manifest_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return manifest_path


def build_readme(outdir: Path, count: int, compressed: bool, compress_level: int) -> None:
    text = f"""
    This directory contains reproducible benign Chinese-language payloads for
    Table-I-style methodology experiments.

    Contents:
      - plain/: UTF-8 plaintext payloads
      - compressed/: zlib-compressed variants {'(present)' if compressed else '(not generated)'}
      - manifest.csv: filenames, sizes, and SHA-256 checksums

    Suggested workflow:
      1. Select a plaintext or compressed payload.
      2. Use it as a file-injection / upload test input.
      3. Download the round-tripped file from the platform.
      4. Compare hashes using payload_tools/hash_compare.py.

    Generation parameters:
      - payload_count: {count}
      - compressed_variants: {compressed}
      - zlib_level: {compress_level if compressed else 'N/A'}

    Note:
      These payloads are benign placeholders written in Chinese. They are meant
      to document and support the evaluation methodology, not to recreate the
      original sensitive keyword corpus used in the live platform study.
    """
    (outdir / "README.txt").write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate benign Chinese-language test payloads for reproducible save-state methodology experiments."
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        default=Path("examples/sample_payloads"),
        help="Output directory for generated files.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=12,
        help="Number of payloads to generate.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1337,
        help="Random seed for deterministic payload generation.",
    )
    parser.add_argument(
        "--compress",
        action="store_true",
        help="Also generate zlib-compressed variants.",
    )
    parser.add_argument(
        "--compress-level",
        type=int,
        default=9,
        choices=range(0, 10),
        metavar="[0-9]",
        help="zlib compression level for compressed variants.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.count <= 0:
        raise SystemExit("--count must be positive")

    plain_dir, compressed_dir = ensure_dirs(args.outdir, with_compressed=args.compress)
    specs = build_payload_specs(count=args.count, seed=args.seed)
    rows = manifest_rows(
        specs=specs,
        plain_dir=plain_dir,
        compressed_dir=compressed_dir,
        compress_level=args.compress_level,
    )
    manifest_path = write_manifest(args.outdir, rows)
    build_readme(
        outdir=args.outdir,
        count=args.count,
        compressed=args.compress,
        compress_level=args.compress_level,
    )

    print(f"[ok] generated {len(rows)} payloads")
    print(f"[ok] manifest: {manifest_path}")
    print(f"[ok] plain payloads: {plain_dir}")
    if compressed_dir is not None:
        print(f"[ok] compressed payloads: {compressed_dir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
