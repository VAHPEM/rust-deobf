use obfstr::obfstr;

fn main() {
    println!("{}", obfstr!("canary::alpha::7f3c-config-endpoint"));
    println!("{}", obfstr!("canary::bravo::build-id-20261018"));
    println!("{}", obfstr!("canary::charlie::/opt/app/resources/data.bin"));
    println!("{}", obfstr!("canary::delta::feature-flag-telemetry-off"));
    println!("{}", obfstr!("canary::echo::schema-version-4"));
}
