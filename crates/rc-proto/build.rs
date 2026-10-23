// protox compiles .proto files in pure Rust, so building needs no `protoc`.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    let fds = protox::compile(
        ["proto/remoteconn.proto", "proto/rendezvous.proto"],
        ["proto"],
    )?;
    prost_build::Config::new().compile_fds(fds)?;
    Ok(())
}
