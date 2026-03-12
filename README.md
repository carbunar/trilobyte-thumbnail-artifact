# Trilobyte Artifact

This repository contains a minimal reference implementation used to generate the qualitative illustration of thumbnail perturbations reported in the paper.

## Qualitative Illustration of Thumbnail Perturbations

The goal of this component is to show that the embedding mechanism used by Trilobyte introduces only low-magnitude visual perturbations to saved-state thumbnails.

Specifically, the repository contains:

- an example original game thumbnail (`cover.png`)
- a corresponding stego thumbnail (`cover_stego.png`)
- a visualization script (`src/heatmap_gen.py`) that computes an amplified pixel-difference heatmap and summary statistics
- a reference embedding script (`src/thumbnail_channel.py`) used for the qualitative example

Running the heatmap script produces:

- a side-by-side comparison figure
- mean absolute pixel difference
- maximum channel perturbation
- number of pixels modified

This qualitative analysis supports the plausibility requirement of the system design: saved-state artifacts modified by the embedding mechanism remain perceptually consistent with ordinary gameplay artifacts at normal viewing scale.

> **Important**
>
> This prototype is intended as an illustrative artifact. It does not reproduce the full Trilobyte system pipeline or its end-to-end threat model.

## Environment

The qualitative thumbnail example was reproduced with **Python 3.10.11**. We recommend using **Python 3.10.11** for best compatibility with the reproduced environment.

## Setup

Create and activate a Python 3.10 virtual environment.

### Windows PowerShell

```powershell
py -3.10 -m venv .venv310
.\\.venv310\\Scripts\\Activate.ps1
python --version
```

The Python version should report `Python 3.10.11`.

Then install the required packages:

```powershell
python -m pip install --upgrade pip setuptools wheel
pip install torch==1.13.1 pillow "numpy<2" matplotlib imageio tqdm steganogan
```

## Patched SteganoGAN Dependency

The qualitative thumbnail illustration uses SteganoGAN as the embedding backend.

In the reproduced environment used for this artifact, the public SteganoGAN package required a small compatibility patch to `models.py`. This repository includes that patched file as:

```text
compat/steganogan_models.py
```

After installing `steganogan`, replace the installed `models.py` with the patched version included in this repository.

### Windows PowerShell Example

```powershell
Copy-Item .\\compat\\steganogan_models.py .\\.venv310\\Lib\\site-packages\\steganogan\\models.py
```

This patch is only needed to run the qualitative thumbnail example included in this artifact.

The patched file is derived from SteganoGAN. Please preserve the original license and attribution information. See:

```text
third_party_licenses/SteganoGAN-MIT-LICENSE.txt
```

## Generating the Qualitative Figure

To generate the pixel-difference heatmap and the side-by-side comparison figure, run:

```powershell
python src\\heatmap_gen.py
```

This produces artifacts such as:

- `cover_diff_heatmap.png`
- `cover_comparison.png`

These files can be used directly in the paper to illustrate thumbnail perturbations.

## Notes on Interpretation

The qualitative figure is intended to illustrate low perceptual distortion. In particular, the side-by-side visualization is used to show that:

- the modified thumbnail remains visually similar to the original at normal viewing scale
- perturbations become visible only after amplification in the heatmap
- the embedding process is consistent with the paper's plausibility argument for hidden-state communication
