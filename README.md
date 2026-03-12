# Trilobyte Thumbnail Artifact (Evaluation Companion)

This artifact accompanies the Trilobyte paper and provides a minimal, evaluation-focused reproduction package for the qualitative and measurement components of the study.

It does not include operational covert-communication deployment code. Instead, it provides:
- reproducible payload preparation methodology (Table I style)
- thumbnail perturbation visualization (Figure 4 style)
- session capacity aggregation logic (Table III style)

This aligns with common artifact practices in censorship-resistant systems research.

## Repository Structure

src/
    session_capacity.py
    crypto.py
    analysis/
        heatmap_gen.py

payload_tools/
    make_test_payloads.py
    encrypt_payloads.py
    hash_compare.py

examples/
    sample_payloads/
        plain/
        encrypted_plain/
        manifests/
    sample_results/
        session_capacity_input.csv

NOTE:
If your local structure is:
examples/sample_payloads/sample_results/
then adjust paths in the commands accordingly.

## Dependencies

Install required Python packages:

pip install cryptography numpy pillow scikit-image

If using SteganoGAN components:

pip install torch torchvision

## 1. Payload Generation (Table I Methodology)

This reproduces the experimental methodology used to test whether platforms accept, store, and return hidden data.

Step 1 — Generate test payloads

python payload_tools/make_test_payloads.py --outdir examples/sample_payloads/plain --count 5 --compress

This creates synthetic placeholder payloads. Original sensitive keyword datasets are not required.

Step 2 — Encrypt payloads

python payload_tools/encrypt_payloads.py --input-dir examples/sample_payloads/plain --outdir examples/sample_payloads/encrypted_plain --master-key-hex 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff --input-kind plain

Step 3 — Verify round-trip integrity

After manually uploading and downloading files through gaming platforms:

python payload_tools/hash_compare.py --dir-a examples/sample_payloads/plain --dir-b path_to_downloaded_files

## 2. Thumbnail Perturbation Visualization (Figure 4)

Heatmap visualization code is located at:

src/analysis/heatmap_gen.py

Example:

python src/analysis/heatmap_gen.py --cover examples/thumbnails/original.png --stego examples/thumbnails/stego.png --out examples/thumbnails/heatmap.png

This reproduces pixel-difference heatmaps, PSNR, and SSIM metrics.

## 3. Session Capacity Aggregation (Table III)

Input file:

examples/sample_results/session_capacity_input.csv

Run:

python src/session_capacity.py --input-csv examples/sample_results/session_capacity_input.csv --out-csv examples/sample_results/session_capacity_output.csv --unit kib

If your repository uses nested structure:

examples/sample_payloads/sample_results/session_capacity_input.csv

then run:

python src/session_capacity.py --input-csv examples/sample_payloads/sample_results/session_capacity_input.csv --out-csv examples/sample_payloads/sample_results/session_capacity_output.csv --unit kib

## Artifact Scope

This artifact reproduces:
- payload preparation methodology
- thumbnail embedding visual evaluation
- capacity aggregation logic

It does not include:
- automated gameplay pipelines
- platform synchronization tooling
- operational covert communication code

These components depend on proprietary ecosystems and user-behavior traces.

## Reproducibility Notes

- Synthetic payloads replace original sensitive datasets
- Capacity values are transcribed from reported measurements
- Thumbnail visualization is fully reproducible
- Unit conventions may differ slightly due to KB vs KiB rounding

## Citation

If you use this artifact, please cite the Trilobyte paper.
