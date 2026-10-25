// Benign goldberg test program. Author-written; no payload, no real indicators.
// Ground truth is in obf_src/goldberg_cff/expected.json.
use goldberg::*;
use std::hint::black_box;

fn band(code: u32) -> u32 {
    // goldberg_stmts! applies code-flow obfuscation (flattening + opaque predicates) here.
    // Only integer locals: goldberg_stmts cannot parse reference-typed locals.
    goldberg_stmts! {
        let mut sel: u32;
        if code < 10 {
            sel = 0u32;
        } else if code < 100 {
            sel = 1u32;
        } else {
            sel = 2u32;
        }
        let mut h: u32 = 2166136261u32;
        let mut n: u32 = code;
        while n > 0 {
            h = (h ^ (n & 0xff)).wrapping_mul(16777619u32);
            n >>= 8;
        }
        if h % 7u32 == 0 {
            sel = 3u32;
        }
        sel
    }
}

fn label(code: u32) -> &'static str {
    match band(code) {
        0 => "low-band-selector",
        1 => "mid-band-selector",
        2 => "high-band-selector",
        _ => "collision-band-selector",
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(42);
    let tag = String::from(goldberg_string!("C:\\ProgramData\\Helios\\agent-state.db"));
    let note = String::from(goldberg_string!("https://cdn.helios-sync.net/v2/push"));
    let secret_const: u32 = goldberg_int!(305419896u32); // 0x12345678
    println!("{} {} {} {}", label(code), tag, note, black_box(secret_const));
}
