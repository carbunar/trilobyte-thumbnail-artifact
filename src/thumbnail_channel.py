from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
from PIL import Image

# matplotlib is only needed for the diff heatmap / figure output
import matplotlib.pyplot as plt

try:
    from steganogan import SteganoGAN
except Exception:
    SteganoGAN = None


# =============================================================================
# Constants
# =============================================================================

SUPPORTED_IMAGE_SUFFIXES = {".png", ".bmp", ".jpg", ".jpeg", ".webp"}
PAYLOAD_MAGIC = "TRILOBYTE_BYTES_V1"


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class ExtractedPayload:
    raw_bytes: bytes
    metadata: dict


@dataclass
class DiffStats:
    mean_abs_diff: float
    max_abs_diff: int
    changed_pixels: int
    total_pixels: int


# =============================================================================
# Helpers
# =============================================================================

def _ensure_steganogan_available() -> None:
    if SteganoGAN is None:
        raise ImportError(
            "Could not import steganogan. Install it first with:\n"
            "    pip install steganogan\n"
            "If that fails, your Python / torch version may be incompatible."
        )


def _ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _validate_image_path(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Image not found: {path}")
    if path.suffix.lower() not in SUPPORTED_IMAGE_SUFFIXES:
        raise ValueError(
            f"Unsupported image type: {path.suffix}. "
            f"Supported: {sorted(SUPPORTED_IMAGE_SUFFIXES)}"
        )


def _load_model(model_name: str = "dense"):
    _ensure_steganogan_available()
    return SteganoGAN.load(model_name)


def _pack_bytes_for_steganogan(payload_bytes: bytes, metadata: Optional[dict] = None) -> str:
    """
    SteganoGAN's public API works with text payloads. We therefore wrap arbitrary
    bytes in a compact JSON envelope and base64-encode the raw bytes.
    """
    envelope = {
        "magic": PAYLOAD_MAGIC,
        "length": len(payload_bytes),
        "data_b64": base64.b64encode(payload_bytes).decode("ascii"),
        "metadata": metadata or {},
    }
    return json.dumps(envelope, separators=(",", ":"))


def _unpack_bytes_from_steganogan(text: str) -> ExtractedPayload:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("Decoded SteganoGAN payload is not valid JSON.") from exc

    if obj.get("magic") != PAYLOAD_MAGIC:
        raise ValueError("Decoded payload does not have the expected Trilobyte marker.")

    if "data_b64" not in obj or "length" not in obj:
        raise ValueError("Decoded payload is missing required fields.")

    raw = base64.b64decode(obj["data_b64"])
    expected_len = int(obj["length"])
    if len(raw) != expected_len:
        raise ValueError(
            f"Decoded payload length mismatch: expected {expected_len}, got {len(raw)}"
        )

    return ExtractedPayload(
        raw_bytes=raw,
        metadata=obj.get("metadata", {}),
    )


# =============================================================================
# Core image operations
# =============================================================================

def load_image(image_path: str | Path) -> Image.Image:
    """
    Load an image as RGB.
    """
    path = Path(image_path)
    _validate_image_path(path)
    return Image.open(path).convert("RGB")


def save_image(image: Image.Image, output_path: str | Path) -> None:
    """
    Save a PIL image, creating parent directories if needed.
    """
    path = Path(output_path)
    _ensure_parent_dir(path)
    image.save(path)


def embed_bytes(
    cover_image_path: str | Path,
    payload_bytes: bytes,
    stego_image_path: str | Path,
    model_name: str = "dense",
    metadata: Optional[dict] = None,
) -> Path:
    """
    Hide arbitrary bytes in an image using SteganoGAN.

    Returns the output path.
    """
    cover_path = Path(cover_image_path)
    stego_path = Path(stego_image_path)

    _validate_image_path(cover_path)
    _ensure_parent_dir(stego_path)

    model = _load_model(model_name=model_name)
    payload_text = _pack_bytes_for_steganogan(payload_bytes, metadata=metadata)

    # SteganoGAN API pattern from project documentation / examples:
    # model.encode(input_path, output_path, message_text)
    model.encode(str(cover_path), str(stego_path), payload_text)
    return stego_path


def extract_bytes(
    stego_image_path: str | Path,
    model_name: str = "dense",
) -> ExtractedPayload:
    """
    Recover arbitrary bytes from a SteganoGAN image.
    """
    stego_path = Path(stego_image_path)
    _validate_image_path(stego_path)

    model = _load_model(model_name=model_name)

    # SteganoGAN API pattern from project documentation / examples:
    # model.decode(stego_path) -> recovered text
    text = model.decode(str(stego_path))
    return _unpack_bytes_from_steganogan(text)


# =============================================================================
# Diff heatmap and figure helpers
# =============================================================================

def compute_abs_diff_arrays(
    original_image_path: str | Path,
    stego_image_path: str | Path,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Returns:
        orig_rgb: H x W x 3 uint8
        stego_rgb: H x W x 3 uint8
        abs_diff: H x W x 3 uint8
    """
    orig = np.array(load_image(original_image_path), dtype=np.uint8)
    stego = np.array(load_image(stego_image_path), dtype=np.uint8)

    if orig.shape != stego.shape:
        raise ValueError(
            f"Image size mismatch: original={orig.shape}, stego={stego.shape}"
        )

    diff = np.abs(orig.astype(np.int16) - stego.astype(np.int16)).astype(np.uint8)
    return orig, stego, diff


def compute_diff_stats(
    original_image_path: str | Path,
    stego_image_path: str | Path,
) -> DiffStats:
    orig, stego, diff = compute_abs_diff_arrays(original_image_path, stego_image_path)

    pixel_changed_mask = np.any(orig != stego, axis=2)
    changed_pixels = int(pixel_changed_mask.sum())
    total_pixels = int(orig.shape[0] * orig.shape[1])

    return DiffStats(
        mean_abs_diff=float(diff.mean()),
        max_abs_diff=int(diff.max()),
        changed_pixels=changed_pixels,
        total_pixels=total_pixels,
    )


def save_diff_heatmap(
    original_image_path: str | Path,
    stego_image_path: str | Path,
    output_heatmap_path: str | Path,
    amplification: float = 32.0,
    grayscale: bool = True,
) -> Path:
    """
    Create an amplified difference visualization.

    If grayscale=True, convert channel-wise absolute differences into a single
    heatmap using per-pixel mean absolute difference.
    """
    _, _, diff = compute_abs_diff_arrays(original_image_path, stego_image_path)
    out_path = Path(output_heatmap_path)
    _ensure_parent_dir(out_path)

    if grayscale:
        diff_map = diff.mean(axis=2).astype(np.float32) * amplification
        diff_map = np.clip(diff_map, 0, 255).astype(np.uint8)
        img = Image.fromarray(diff_map, mode="L")
    else:
        diff_map = diff.astype(np.float32) * amplification
        diff_map = np.clip(diff_map, 0, 255).astype(np.uint8)
        img = Image.fromarray(diff_map, mode="RGB")

    img.save(out_path)
    return out_path


def save_comparison_figure(
    original_image_path: str | Path,
    stego_image_path: str | Path,
    output_figure_path: str | Path,
    amplification: float = 32.0,
    title: Optional[str] = None,
    annotate_stats: bool = True,
) -> Path:
    """
    Save a 3-panel figure:
        original | stego | amplified diff heatmap
    """
    orig, stego, diff = compute_abs_diff_arrays(original_image_path, stego_image_path)
    stats = compute_diff_stats(original_image_path, stego_image_path)

    diff_map = diff.mean(axis=2).astype(np.float32) * amplification
    diff_map = np.clip(diff_map, 0, 255)

    out_path = Path(output_figure_path)
    _ensure_parent_dir(out_path)

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    axes[0].imshow(orig)
    axes[0].set_title("Original thumbnail")
    axes[0].axis("off")

    axes[1].imshow(stego)
    axes[1].set_title("Stego thumbnail")
    axes[1].axis("off")

    im = axes[2].imshow(diff_map, cmap="hot")
    axes[2].set_title(f"Amplified abs diff (x{amplification:g})")
    axes[2].axis("off")
    fig.colorbar(im, ax=axes[2], fraction=0.046, pad=0.04)

    if title:
        fig.suptitle(title, fontsize=12)

    if annotate_stats:
        changed_pct = 100.0 * stats.changed_pixels / max(stats.total_pixels, 1)
        stats_text = (
            f"Mean abs diff: {stats.mean_abs_diff:.4f}\n"
            f"Max abs diff: {stats.max_abs_diff}\n"
            f"Changed pixels: {stats.changed_pixels}/{stats.total_pixels} "
            f"({changed_pct:.2f}%)"
        )
        fig.text(0.5, 0.01, stats_text, ha="center", va="bottom", fontsize=9)

    fig.tight_layout(rect=(0, 0.05, 1, 0.95))
    fig.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return out_path


# =============================================================================
# Convenience workflows
# =============================================================================

def embed_file_bytes(
    cover_image_path: str | Path,
    input_file_path: str | Path,
    stego_image_path: str | Path,
    model_name: str = "dense",
    metadata: Optional[dict] = None,
) -> Path:
    """
    Read a file as bytes and embed it.
    """
    input_path = Path(input_file_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    payload_bytes = input_path.read_bytes()
    merged_metadata = {
        "source_filename": input_path.name,
        "source_num_bytes": len(payload_bytes),
    }
    if metadata:
        merged_metadata.update(metadata)

    return embed_bytes(
        cover_image_path=cover_image_path,
        payload_bytes=payload_bytes,
        stego_image_path=stego_image_path,
        model_name=model_name,
        metadata=merged_metadata,
    )


def extract_file_bytes(
    stego_image_path: str | Path,
    output_file_path: str | Path,
    model_name: str = "dense",
) -> Path:
    """
    Extract bytes from a stego image and write them to a file.
    """
    result = extract_bytes(stego_image_path=stego_image_path, model_name=model_name)
    out_path = Path(output_file_path)
    _ensure_parent_dir(out_path)
    out_path.write_bytes(result.raw_bytes)
    return out_path


# =============================================================================
# Example self-test / demo
# =============================================================================

def _demo() -> None:
    cover = Path("data/input/cover.png")
    stego = Path("outputs/stego/cover_stego.png")

    if not cover.exists():
        print("Demo skipped: place a cover image at data/input/cover.png")
        return

    model = _load_model("dense")
    test_message = "hello"

    print("[1] Embedding plain text...")
    model.encode(str(cover), str(stego), test_message)
    print(f"    Wrote stego image: {stego}")

    print("[2] Decoding plain text...")
    recovered = model.decode(str(stego))
    print(f"    Decoded: {recovered!r}")

# def _demo() -> None:
#     """
#     Example usage:
#         python src/thumbnail_channel.py

#     Before running:
#       1. Put a cover image at data/input/cover.png
#       2. Install dependencies
#     """
#     cover = Path("data/input/cover.png")
#     stego = Path("outputs/stego/cover_stego.png")
#     recovered = Path("outputs/recovered/payload.bin")
#     heatmap = Path("outputs/figures/cover_diff_heatmap.png")
#     figure = Path("outputs/figures/cover_comparison.png")

#     if not cover.exists():
#         print("Demo skipped: place a cover image at data/input/cover.png")
#         return

#     payload = b"hello from Trilobyte thumbnail channel"

#     print("[1] Embedding bytes...")
#     embed_bytes(
#         cover_image_path=cover,
#         payload_bytes=payload,
#         stego_image_path=stego,
#         metadata={"demo": True},
#     )
#     print(f"    Wrote stego image: {stego}")

#     print("[2] Extracting bytes...")
#     result = extract_bytes(stego)
#     recovered.parent.mkdir(parents=True, exist_ok=True)
#     recovered.write_bytes(result.raw_bytes)
#     print(f"    Extracted {len(result.raw_bytes)} bytes to: {recovered}")
#     print(f"    Metadata: {result.metadata}")

#     print("[3] Saving amplified diff heatmap...")
#     save_diff_heatmap(cover, stego, heatmap, amplification=32.0)
#     print(f"    Wrote heatmap: {heatmap}")

#     print("[4] Saving 3-panel comparison figure...")
#     save_comparison_figure(
#         cover,
#         stego,
#         figure,
#         amplification=32.0,
#         title="Trilobyte qualitative thumbnail example",
#         annotate_stats=True,
#     )
#     print(f"    Wrote figure: {figure}")

#     stats = compute_diff_stats(cover, stego)
#     print("[5] Diff stats:")
#     print(f"    mean_abs_diff={stats.mean_abs_diff:.6f}")
#     print(f"    max_abs_diff={stats.max_abs_diff}")
#     print(f"    changed_pixels={stats.changed_pixels}/{stats.total_pixels}")

#     assert result.raw_bytes == payload
#     print("thumbnail_channel.py demo passed.")


if __name__ == "__main__":
    _demo()
