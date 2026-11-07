fn main() {
    // SQLx embeds existing files, but stable Rust does not track newly added
    // migration files unless the containing directory is an explicit input.
    println!("cargo:rerun-if-changed=migrations");
}
