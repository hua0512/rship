//! Azure Blob Storage REST API (`2023-11-03`) [`rship_core::backend::StorageBackend`].
//!
//! Supports SharedKey HMAC-SHA256 signing (via shared [`crate::common::crypto::hmac_sha256`]),
//! SAS token / SAS URL authentication, anonymous public containers, and Azurite emulator;
//! parallel `Put Block` (`UploadTopology::ParallelParts`) + `Get Block List` uncommitted-block
//! crash-resume + `Put Block List` commit; `x-ms-copy-source` server-side copy with `pending`
//! status polling; `Content-MD5` verification; version-pinned `If-Match` Range downloads;
//! and `rclone.conf` (`type = azureblob`) import.

pub mod auth;
pub mod backend;
pub mod config;
pub mod rclone_import;
pub mod xml;

pub use auth::{
    AZURE_API_VERSION, AzureAuth, canonicalize_headers, canonicalize_resource,
    sign_shared_key_request,
};
pub use backend::AzureBlobBackend;
pub use config::{
    AZURE_MAX_BLOCK_BYTES, AZURE_MAX_BLOCKS, AZURE_MAX_OBJECT_BYTES, AZURE_MIN_BLOCK_BYTES,
    AzureBlobConfig, DEFAULT_AZURE_BLOCK_SIZE, DEFAULT_AZURE_SINGLE_SHOT_MAX,
    azure_encode_blob_path,
};
pub use rclone_import::{
    ImportedRcloneAzureBlob, RcloneAzureBlobImportReport, SasUrlMetadata,
    extract_sas_account_and_endpoint, extract_sas_url_metadata, parse_rclone_azureblob_conf,
};
