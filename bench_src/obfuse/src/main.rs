use obfuse::obfuse;

fn main() {
    println!("{}", obfuse!("canary::alpha::7f3c-config-endpoint", seed = "rust-deobf-bench-a3b6836757f5d3ff").as_str());
    println!("{}", obfuse!("canary::bravo::build-id-20261018", seed = "rust-deobf-bench-0b862966a17824ec").as_str());
    println!("{}", obfuse!("canary::charlie::/opt/app/resources/data.bin", seed = "rust-deobf-bench-f69472c80705a50a").as_str());
    println!("{}", obfuse!("canary::delta::feature-flag-telemetry-off", seed = "rust-deobf-bench-cc7a00967d09c17f").as_str());
    println!("{}", obfuse!("canary::echo::schema-version-4", seed = "rust-deobf-bench-abc8090f2b988c8a").as_str());
}
