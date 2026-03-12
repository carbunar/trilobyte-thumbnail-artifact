This directory contains reproducible benign Chinese-language payloads for
Table-I-style methodology experiments.

Contents:
  - plain/: UTF-8 plaintext payloads
  - compressed/: zlib-compressed variants (present)
  - manifest.csv: filenames, sizes, and SHA-256 checksums

Suggested workflow:
  1. Select a plaintext or compressed payload.
  2. Use it as a file-injection / upload test input.
  3. Download the round-tripped file from the platform.
  4. Compare hashes using payload_tools/hash_compare.py.

Generation parameters:
  - payload_count: 12
  - compressed_variants: True
  - zlib_level: 9

Note:
  These payloads are benign placeholders written in Chinese. They are meant
  to document and support the evaluation methodology, not to recreate the
  original sensitive keyword corpus used in the live platform study.
