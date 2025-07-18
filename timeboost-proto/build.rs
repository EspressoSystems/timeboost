use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    tonic_build::configure()
        .build_server(true)
        .out_dir("src")
        .bytes([".block.Block.payload", ".inclusion.Transaction.encoded_txn"])
        .compile_protos(
            &[
                "protos/inclusion_list.proto",
                "protos/block.proto",
                "protos/internal.proto",
                "protos/forward.proto",
            ],
            &["protos/"],
        )?;
    Ok(())
}
