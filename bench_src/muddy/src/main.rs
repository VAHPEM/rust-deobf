use muddy::muddy;

fn main() {
    println!("{}", muddy!("canary::alpha::7f3c-config-endpoint"));
    println!("{}", muddy!("canary::bravo::build-id-20261018"));
    println!("{}", muddy!("canary::charlie::/opt/app/resources/data.bin"));
    println!("{}", muddy!("canary::delta::feature-flag-telemetry-off"));
    println!("{}", muddy!("canary::echo::schema-version-4"));
}
