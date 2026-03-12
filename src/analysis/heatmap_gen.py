from pathlib import Path

import numpy as np
from PIL import Image
import matplotlib.pyplot as plt


def load_rgb(path: str) -> np.ndarray:
    return np.array(Image.open(path).convert("RGB"), dtype=np.uint8)


def main() -> None:
    original_path = "cover.png"
    stego_path = "cover_stego.png"

    heatmap_path = "cover_diff_heatmap.png"
    figure_path = "cover_comparison.png"

    original = load_rgb(original_path)
    stego = load_rgb(stego_path)

    if original.shape != stego.shape:
        raise ValueError(f"Shape mismatch: {original.shape} vs {stego.shape}")

    # Absolute per-channel pixel differences
    diff = np.abs(original.astype(np.int16) - stego.astype(np.int16)).astype(np.uint8)

    # Collapse RGB differences into one grayscale map
    diff_gray = diff.mean(axis=2).astype(np.float32)

    # Amplify so differences are visible
    amplification = 32.0
    diff_amp = np.clip(diff_gray * amplification, 0, 255).astype(np.uint8)

    Image.fromarray(diff_amp, mode="L").save(heatmap_path)

    mean_abs_diff = float(diff.mean())
    max_abs_diff = int(diff.max())
    changed_pixels = int((original != stego).any(axis=2).sum())
    total_pixels = int(original.shape[0] * original.shape[1])

    print(f"mean_abs_diff = {mean_abs_diff:.6f}")
    print(f"max_abs_diff = {max_abs_diff}")
    print(f"changed_pixels = {changed_pixels}/{total_pixels}")

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    axes[0].imshow(original)
    axes[0].set_title("Original thumbnail")
    axes[0].axis("off")

    axes[1].imshow(stego)
    axes[1].set_title("Stego thumbnail")
    axes[1].axis("off")

    im = axes[2].imshow(diff_amp, cmap="hot")
    axes[2].set_title(f"Amplified abs diff x{amplification:g}")
    axes[2].axis("off")
    fig.colorbar(im, ax=axes[2], fraction=0.046, pad=0.04)

    fig.tight_layout()
    fig.savefig(figure_path, dpi=200, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    main()
