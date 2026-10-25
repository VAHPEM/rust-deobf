fn main() {
    println!("{}", cryptify::encrypt_string!("canary::alpha::7f3c-config-endpoint"));
    println!("{}", cryptify::encrypt_string!("canary::bravo::build-id-20261018"));
    println!("{}", cryptify::encrypt_string!("canary::charlie::/opt/app/resources/data.bin"));
    println!("{}", cryptify::encrypt_string!("canary::delta::feature-flag-telemetry-off"));
    println!("{}", cryptify::encrypt_string!("canary::echo::schema-version-4"));
}
