fn main() {
    prost_build::Config::new()
        .out_dir("src")
        .compile_protos(&["src/inclusion_list.proto"], &["src/"])
        .unwrap();
}
