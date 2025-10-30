//! This build script copies the `memory.x` file from the crate root into
//! a directory where the linker can always find it at build time.
//! For many projects this is optional, as the linker always searches the
//! project root directory -- wherever `Cargo.toml` is. However, if you
//! are using a workspace or have a more complicated build setup, this
//! build script becomes required. Additionally, by requesting that
//! Cargo re-run the build script whenever `memory.x` is changed,
//! updating `memory.x` ensures a rebuild of the application with the
//! new memory settings.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    // Put `memory.x` in our output directory and ensure it's
    // on the linker search path.
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());

    #[cfg(not(feature = "skip-cyw43-firmware"))]
    download_cyw43_firmware();

    // By default, Cargo will re-run a build script whenever
    // any file in the project changes. By specifying `memory.x`
    // here, we ensure the build script is only re-run when
    // `memory.x` is changed.
    println!("cargo:rerun-if-changed=memory.x");

    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");
}

#[cfg(not(feature = "skip-cyw43-firmware"))]
fn download_cyw43_firmware() {
    let download_folder = "cyw43-firmware";
    let url_base = "https://github.com/embassy-rs/embassy/raw/refs/heads/main/cyw43-firmware";
    let file_names = [
        "43439A0.bin",
        "43439A0_btfw.bin",
        "43439A0_clm.bin",
        "LICENSE-permissive-binary-license-1.0.txt",
        "README.md",
    ];

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", download_folder);
    std::fs::create_dir_all(download_folder).expect("Failed to create download directory");

    // download each file into the folder "cyw43-firmware"
    for file in file_names {
        let url = format!("{}/{}", url_base, file);
        // only fetch if it doesn't exist
        if std::path::Path::new(download_folder).join(file).exists() {
            continue;
        }
        match reqwest::blocking::get(&url) {
            Ok(response) => {
                let content = response.bytes().expect("Failed to read file content");
                let file_path = PathBuf::from(download_folder).join(file);
                std::fs::write(file_path, &content).expect("Failed to write file");
            }
            Err(err) => panic!(
                "Failed to download the cyw43 firmware from {}: {}, required for pi-pico-w example",
                url, err
            ),
        }
    }
}
