static XOR_KEY: [u8; 16] = [221,10,33,101,67,233,179,250,158,235,160,154,120,31,236,91];
static SENC_0: [u8; 15] = [236,58,15,83,117,199,130,200,176,220,154,162,76,43,223];
static SENC_1: [u8; 36] = [158,48,125,53,49,134,212,136,255,134,228,251,12,126,176,21,178,120,85,13,52,128,221,158,205,157,195,198,11,107,141,47,184,36,69,7];
static SENC_2: [u8; 16] = [154,102,78,7,34,133,239,180,201,198,149,249,73,122,213,58];
static SENC_3: [u8; 49] = [181,126,85,21,48,211,156,213,234,142,204,255,21,122,152,41,164,36,79,10,49,157,219,141,247,133,196,180,29,103,141,54,173,102,68,74,34,153,218,213,232,216,143,248,29,126,143,52,179];
static SENC_4: [u8; 60] = [144,101,91,12,47,133,210,213,171,197,144,186,80,72,133,53,185,101,86,22,99,167,231,218,175,219,142,170,67,63,187,50,179,60,21,94,99,145,133,206,183,203,238,245,10,107,132,44,180,100,69,36,36,140,221,142,177,217,142,171];
static SENC_5: [u8; 19] = [240,39,82,14,42,153,158,143,238,143,193,238,29,50,143,51,184,105,74];
static SENC_6: [u8; 33] = [142,101,71,17,52,136,193,159,194,165,207,232,12,119,155,50,179,110,125,36,36,140,221,142,194,184,197,238,12,118,130,60,174];
static SENC_7: [u8; 23] = [179,125,12,4,36,140,221,142,164,209,211,238,25,120,137,102,190,101,77,9,38,138,199];
#[inline(never)]
fn dex(enc: &[u8]) -> String {
    let mut out = Vec::with_capacity(enc.len());
    for (i, b) in enc.iter().enumerate() { out.push(b ^ XOR_KEY[i % XOR_KEY.len()]); }
    String::from_utf8(out).unwrap()
}

struct Config {
    c2: String,
    cache: String,
    agent: String,
}

#[inline(never)]
fn load_config() -> Config {
    Config { c2: dex(&SENC_0), cache: dex(&SENC_1), agent: dex(&SENC_4) }
}

#[inline(never)]
fn already_running(name: &str) -> bool {
    let name = std::hint::black_box(name);
    name == dex(&SENC_2)
}

#[inline(never)]
fn endpoint(kind: usize) -> String {
    match kind {
        0 => dex(&SENC_3),
        1 => dex(&SENC_7),
        _ => String::new(),
    }
}

#[inline(never)]
fn skip_update(args: &[String]) -> bool {
    args.iter().any(|a| { let a = a.as_str(); a == dex(&SENC_5) })
}

#[inline(never)]
fn settings_key() -> String {
    dex(&SENC_6)
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
