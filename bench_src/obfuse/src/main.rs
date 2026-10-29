use obfuse::obfuse;

fn main() {
    println!("{}", obfuse!("canary::alpha::7f3c-config-endpoint").as_str());
    println!("{}", obfuse!("canary::bravo::build-id-20261018").as_str());
    println!("{}", obfuse!("canary::charlie::/opt/app/resources/data.bin").as_str());
    println!("{}", obfuse!("canary::delta::feature-flag-telemetry-off").as_str());
    println!("{}", obfuse!("canary::echo::schema-version-4").as_str());
}
