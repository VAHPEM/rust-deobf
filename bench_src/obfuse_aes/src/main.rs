use obfuse::obfuse;

fn main() {
    println!("{}", obfuse!("canary::alpha::7f3c-config-endpoint", seed = "rust-deobf-bench-65ab4fbb4413304b").as_str());
    println!("{}", obfuse!("canary::bravo::build-id-20261018", seed = "rust-deobf-bench-5b19ad491af68b6c").as_str());
    println!("{}", obfuse!("canary::charlie::/opt/app/resources/data.bin", seed = "rust-deobf-bench-ce28a010db12ed9d").as_str());
    println!("{}", obfuse!("canary::delta::feature-flag-telemetry-off", seed = "rust-deobf-bench-53a178354651e992").as_str());
    println!("{}", obfuse!("canary::echo::schema-version-4", seed = "rust-deobf-bench-671db13c03363fa8").as_str());
}
