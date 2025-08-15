use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    tonic_prost_build::configure()
        .build_server(true)
        .out_dir("src")
        .bytes(".block.Block.payload")
        .bytes(".inclusion.Transaction.encoded_txn")
        .bytes(".certified_block.Block.payload")
        .compile_protos(
            &[
                "protos/inclusion_list.proto",
                "protos/block.proto",
                "protos/internal.proto",
                "protos/forward.proto",
                "protos/certified_block.proto",
            ],
            &["protos/"],
        )?;
    Ok(())
}
