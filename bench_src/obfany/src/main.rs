use obfany::{obfnum, obfstmt, obfstr, obfwide};

fn main() {
    println!("{}", obfstr!("canary::alpha::7f3c-config-endpoint"));
    println!("{}", obfstr!("canary::bravo::build-id-20261018"));
    println!("{}", String::from_utf16_lossy(obfwide!("canary::charlie::/opt/app/resources/data.bin")));
    let mut schema: u32 = 0;
    obfstmt! {
        println!("{}", obfstr!("canary::delta::feature-flag-telemetry-off"));
        schema = obfnum!(u32, 4);
        println!("{}", obfstr!("canary::echo::schema-version-4"));
    }
    println!("{}", schema);
}
