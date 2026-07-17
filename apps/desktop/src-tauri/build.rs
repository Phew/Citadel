use std::fs;
use std::path::Path;

fn main() {
    // `tauri::generate_context!` requires frontendDist to exist at compile time.
    // Real assets come from `pnpm build`; for `cargo test` / first compile we
    // ensure a minimal placeholder so the mock command surface can typecheck.
    let dist = Path::new("../dist");
    if !dist.join("index.html").exists() {
        fs::create_dir_all(dist).expect("create apps/desktop/dist placeholder");
        fs::write(
            dist.join("index.html"),
            "<!doctype html><title>Citadel (build placeholder)</title>\n",
        )
        .expect("write dist/index.html placeholder");
    }
    tauri_build::build()
}
