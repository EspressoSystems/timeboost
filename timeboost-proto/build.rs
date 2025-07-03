fn main() {
    prost_build::Config::new()
        .out_dir("src")
        .bytes([".block.Block.payload"])
        .compile_protos(
            &["protos/inclusion_list.proto", "protos/block.proto"],
            &["protos/"],
        )
        .unwrap();
}
