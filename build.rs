// sqlx::migrate! embeds migrations/ at compile time but cargo doesn't know it
// reads that directory: without this a new migration file isn't picked up
// until something else forces a rebuild.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
