fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo");
    let output_dir = format!("{out_dir}/contracts");
    abigen::generate_bindings_for_dir("./abis", output_dir, abigen::BuildType::Ethers)
}
