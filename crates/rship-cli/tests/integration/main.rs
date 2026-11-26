mod auth_and_config;
mod crypt_and_fs;
mod transfers;

pub(crate) fn rship_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rship")
}
