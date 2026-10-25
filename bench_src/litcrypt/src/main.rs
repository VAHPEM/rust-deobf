#[macro_use]
extern crate litcrypt;

use_litcrypt!();
fn main() {
    println!("{}", lc!("canary::alpha::7f3c-config-endpoint"));
    println!("{}", lc!("canary::bravo::build-id-20261018"));
    println!("{}", lc!("canary::charlie::/opt/app/resources/data.bin"));
    println!("{}", lc!("canary::delta::feature-flag-telemetry-off"));
    println!("{}", lc!("canary::echo::schema-version-4"));
}
