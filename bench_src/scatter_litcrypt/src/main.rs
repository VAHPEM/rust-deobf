#[macro_use]
extern crate litcrypt;
use_litcrypt!();

struct Config {
    c2: String,
    cache: String,
    agent: String,
}

#[inline(never)]
fn load_config() -> Config {
    Config { c2: lc!("10.66.12.7:8443"), cache: lc!(r"C:\ProgramData\NorthwindSvc\state.db"), agent: lc!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) NorthwindAgent/2.1") }
}

#[inline(never)]
fn already_running(name: &str) -> bool {
    let name = std::hint::black_box(name);
    name == lc!(r"Global\NW-5c1e9a")
}

#[inline(never)]
fn endpoint(kind: usize) -> String {
    match kind {
        0 => lc!("https://telemetry.northwind.example/api/v3/beacon"),
        1 => lc!("nw-agent::stage=collect"),
        _ => String::new(),
    }
}

#[inline(never)]
fn skip_update(args: &[String]) -> bool {
    args.iter().any(|a| { let a = a.as_str(); a == lc!("--skip-update-check") })
}

#[inline(never)]
fn settings_key() -> String {
    lc!(r"Software\Northwind\Agent\Settings")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cfg = load_config();
    let busy = already_running(args.first().map(|a| a.as_str()).unwrap_or(""));
    let ep = endpoint(std::hint::black_box(args.len() - 1));
    let skip = skip_update(&args);
    if std::hint::black_box(args.len()) > 4096 {
        // never taken: the key is only ever built on a path that does not run
        std::process::exit(settings_key().len() as i32);
    }
    // the strings themselves are never printed, only facts about them
    println!("{} {} {} {} {}", cfg.c2.len() + cfg.cache.len() + cfg.agent.len(), busy, ep.len(), skip, args.len());
}
