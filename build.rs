//! Build script for OmniScope
//!
//! This script handles build-time configuration and code generation.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Get output directory
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("build_info.rs");

    // Generate build information
    let build_info = format!(
        r#"/// Build information
pub const BUILD_TIME: &str = "{}";
pub const RUSTC_VERSION: &str = "{}";
pub const TARGET: &str = "{}";
"#,
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        rustc_version_runtime(),
        env::var("TARGET").unwrap_or_else(|_| "unknown".to_string()),
    );

    fs::write(&dest_path, build_info).unwrap();

    // Tell Cargo to rerun this script if environment changes
    println!("cargo:rerun-if-env-changed=TARGET");

    // Print build info
    println!("cargo:warning=Building OmniScope...");
    println!(
        "cargo:warning=Target: {}",
        env::var("TARGET").unwrap_or_else(|_| "unknown".to_string())
    );
}

fn rustc_version_runtime() -> String {
    // Try to get rustc version
    if let Ok(output) = std::process::Command::new("rustc")
        .arg("--version")
        .output()
    {
        if output.status.success() {
            return String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }
    "unknown".to_string()
}
