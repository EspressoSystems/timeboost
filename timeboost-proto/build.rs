fn main() {
    prost_build::Config::new()
        .out_dir("src")
        .bytes([".block.Block.payload"])
        .compile_protos(&["src/inclusion_list.proto", "src/block.proto"], &["src/"])
        .unwrap();
}
