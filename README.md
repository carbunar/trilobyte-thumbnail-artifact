# Trilobyte Evaluation Companion Artifact

This repository is an **evaluation companion artifact** for the Trilobyte paper.  
It is a **reproduction package for the qualitative and measurement analyses reported in the paper**, not a public release of the full Trilobyte system.

The artifact is intentionally scoped to support independent verification of selected empirical results. It includes code for:

- generating reproducible benign test payloads used in save-state experiments,
- encrypting payloads into Trilobyte-style segments and verifying integrity,
- visualizing thumbnail perturbations introduced by embedding, and
- reproducing session-capacity aggregation results.

---------------------------------------------------------------------

## Scope

### This artifact reproduces

- payload preparation methodology used in save-state experiments,
- encryption and integrity verification workflows,
- qualitative thumbnail perturbation visualizations,
- session-capacity aggregation logic used for reported measurements.

---------------------------------------------------------------------

## Repository Structure

compat/
    steganogan_models.py

data/
    input/
        cover.png

examples/
    sample_payloads/
        manifest.csv
        plain/
        compressed/
        encrypted_plain/
        sample_results/
            session_capacity_input.csv
            session_capacity_output.csv

outputs/
    stego/
        cover_stego.png
        cover_diff_heatmap.png

payload_tools/
    make_test_payloads.py
    encrypt_payloads.py
    hash_compare.py

src/
    crypto.py
    session_capacity.py
    thumbnail_channel.py
    analysis/
        heatmap_gen.py

---------------------------------------------------------------------

## Mapping to Paper Claims

Save-state methodology:
    payload_tools/make_test_payloads.py
    payload_tools/encrypt_payloads.py
    payload_tools/hash_compare.py

Thumbnail perturbation illustration:
    src/analysis/heatmap_gen.py
    src/thumbnail_channel.py

Session-capacity aggregation:
    src/session_capacity.py

---------------------------------------------------------------------

## Installation

Install dependencies:

    pip install -r requirements.txt

Dependencies:

- cryptography
- pillow
- numpy
- matplotlib
- torch
- torchvision
- opencv-python
- steganogan

Note: SteganoGAN installation may be environment-sensitive.  
All non-thumbnail workflows run without it.

---------------------------------------------------------------------

## Quick Start

### Generate benign payloads

    python payload_tools/make_test_payloads.py \
        --outdir examples/sample_payloads \
        --count 12 \
        --seed 1337 \
        --compress

### Encrypt payloads

    python payload_tools/encrypt_payloads.py \
        --input-dir examples/sample_payloads/plain \
        --outdir examples/sample_payloads/encrypted_plain \
        --master-key-hex 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

### Verify integrity after platform upload/download

    python payload_tools/hash_compare.py \
        --dir-a examples/sample_payloads/plain \
        --dir-b path_to_downloaded_files \
        --suffix-filter .txt

---------------------------------------------------------------------

## Thumbnail Perturbation Visualization

From repository root:

    cp data/input/cover.png cover.png
    cp outputs/stego/cover_stego.png cover_stego.png
    python src/analysis/heatmap_gen.py

Produces:

- difference heatmap
- visual comparison figure
- pixel-difference statistics

NOTE:  
The current script computes pixel-difference statistics only.  
PSNR / SSIM values reported in the paper were produced by a separate analysis workflow.

---------------------------------------------------------------------

## Session Capacity Aggregation

    python src/session_capacity.py \
        --input-csv examples/sample_payloads/sample_results/session_capacity_input.csv \
        --out-csv examples/sample_payloads/sample_results/session_capacity_output.csv

---------------------------------------------------------------------

## Reproducibility Notes

- Payload generation workflow is fully reproducible.
- Encryption and integrity verification workflow is reproducible.
- Thumbnail visualization workflow is reproducible for provided examples.
- Capacity aggregation is reproducible from included CSV.
- Full platform experiments depend on external gaming ecosystems and are not reproduced end-to-end.
- Synthetic benign payloads replace original sensitive datasets.

---------------------------------------------------------------------

## Intended Use

This repository should be interpreted as an **evaluation artifact** accompanying the paper.  
It supports verification of experimental methodology and analysis results.

It is **not** a release of the operational Trilobyte system.

---------------------------------------------------------------------

## Ethics and Release Posture

The artifact deliberately excludes components that would materially facilitate real-world covert communication deployment.  
This release scope balances reproducibility with responsible disclosure.

---------------------------------------------------------------------

## Citation

If you use this artifact, please cite the Trilobyte paper.
