use std::io::Write;
static W0: [u16; 35] = [23135,23133,23122,23133,23118,23109,23046,23046,23133,23120,23116,23124,23133,23046,23046,23051,23130,23055,23135,23057,23135,23123,23122,23130,23125,23131,23057,23129,23122,23128,23116,23123,23125,23122,23112];
static W1: [u16; 32] = [23135,23133,23122,23133,23118,23109,23046,23046,23134,23118,23133,23114,23123,23046,23046,23134,23113,23125,23120,23128,23057,23125,23128,23057,23054,23052,23054,23050,23053,23052,23053,23044];
static B64: &str = "Y2FuYXJ5OjpjaGFybGllOjovb3B0L2FwcC9yZXNvdXJjZXMvZGF0YS5iaW4=";
static HEX: &str = "63616e6172793a3a64656c74613a3a666561747572652d666c61672d74656c656d657472792d6f6666";
static Z: [u8; 38] = [120,218,75,78,204,75,44,170,180,178,74,77,206,200,183,178,42,78,206,72,205,77,212,45,75,45,42,206,204,207,211,53,1,0,173,177,11,11];
#[inline(never)]
fn wide(enc: &[u16]) -> Vec<u16> { enc.iter().map(|u| u ^ 0x5a3c).collect() }
#[inline(never)]
fn b64(s: &str) -> String {
    let mut acc = 0u32; let mut n = 0; let mut out = Vec::new();
    for c in s.bytes() {
        let v = match c { b'A'..=b'Z' => c - b'A', b'a'..=b'z' => c - b'a' + 26,
                          b'0'..=b'9' => c - b'0' + 52, b'+' => 62, b'/' => 63, _ => continue };
        acc = (acc << 6) | v as u32; n += 6;
        if n >= 8 { n -= 8; out.push((acc >> n) as u8); }
    }
    String::from_utf8(out).unwrap()
}
#[inline(never)]
fn unhex(s: &str) -> String {
    let h = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
    String::from_utf8(s.as_bytes().chunks(2).map(|p| h(p[0]) << 4 | h(p[1])).collect()).unwrap()
}
#[inline(never)]
fn inflate(z: &[u8]) -> String {
    String::from_utf8(miniz_oxide::inflate::decompress_to_vec_zlib(z).unwrap()).unwrap()
}
#[inline(never)]
fn put_wide(w: &[u16]) {
    let bytes: Vec<u8> = w.iter().flat_map(|u| u.to_le_bytes()).collect();
    std::io::stdout().write_all(&bytes).unwrap();
    println!();
}

fn main() {
    println!("{}", String::from_utf16(&wide(&W0)).unwrap());
    put_wide(&wide(&W1));
    println!("{}", b64(B64));
    println!("{}", unhex(HEX));
    println!("{}", inflate(&Z));
}
