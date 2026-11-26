# `rship` Fuzzing Suite (`cargo-fuzz`)

Standalone [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html) workspace (`fuzz/Cargo.toml` defines its own `[workspace]`) covering untrusted protocol parsers, configuration codecs, and authenticated decryption routines without affecting root workspace `--locked` builds.

## Targets

| Target | Surface Fuzzed |
| :--- | :--- |
| `s3_xml` | `rship_backends::s3::xml`: `parse_list_objects_v2`, `parse_list_parts`, `parse_initiate_multipart_upload`, `parse_complete_multipart_response`, `parse_copy_result`, `parse_delete_objects_response`, `parse_list_multipart_uploads`, `parse_s3_error_xml` |
| `azure_xml` | `rship_backends::azureblob::xml`: `parse_list_blobs`, `parse_block_list`, `parse_azure_error_xml`, `normalize_azure_etag` |
| `webdav_xml` | `rship_backends::webdav::xml`: `parse_multistatus`, `parse_dav_timestamp_ns` |
| `rclone_ini` | `rship_core::rclone_ini`: `parse_rclone_ini`, `reveal_rclone_obscured`, `reveal_or_passthrough_rclone_secret`, `obscure_rclone_secret_with_iv` round-trip, and `Debug` secret redaction |
| `crypt_decrypt` | `rship_crypto::stream` & `rship_crypto::filename`: `StreamHeader::decode`, `decrypt_chunk`, `decrypt_chunk_in_place` (zeroize-on-error invariant), `ciphertext_size`/`plaintext_size` arithmetic, tamper rejection, and `decrypt_segment` |

## Prerequisites

`cargo-fuzz` uses libFuzzer + AddressSanitizer and requires a Rust **nightly** toolchain (best supported on Linux and macOS):

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Running Fuzz Targets

From the repository root:

```bash
# List all configured targets
cargo +nightly fuzz list --fuzz-dir fuzz

# Run a single target (Ctrl+C to stop)
cargo +nightly fuzz run s3_xml --fuzz-dir fuzz

# Run a bounded smoke campaign (e.g. 60 seconds)
cargo +nightly fuzz run crypt_decrypt --fuzz-dir fuzz -- -max_total_time=60

# Reproduce a crash artifact
cargo +nightly fuzz run s3_xml fuzz/artifacts/s3_xml/crash-... --fuzz-dir fuzz
```

You can also list targets via `just fuzz-list`.
