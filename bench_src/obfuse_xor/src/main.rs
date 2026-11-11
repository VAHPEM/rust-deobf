use obfuse::obfuse;

fn main() {
    println!("{}", obfuse!("canary::alpha::7f3c-config-endpoint", seed = "rust-deobf-bench-fcbdeafe22f21cc7").as_str());
    println!("{}", obfuse!("canary::bravo::build-id-20261018", seed = "rust-deobf-bench-783c2dfc79b029da").as_str());
    println!("{}", obfuse!("canary::charlie::/opt/app/resources/data.bin", seed = "rust-deobf-bench-f5e314c336270d41").as_str());
    println!("{}", obfuse!("canary::delta::feature-flag-telemetry-off", seed = "rust-deobf-bench-82e0a57d837da75a").as_str());
    println!("{}", obfuse!("canary::echo::schema-version-4", seed = "rust-deobf-bench-78bc7988a65c877f").as_str());
}
