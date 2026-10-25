#[inline(never)]
fn tight_0() -> String {
    let mut buf: [u8; 35] = [162,134,110,119,179,158,58,44,160,139,112,126,160,221,58,33,167,212,99,59,162,136,110,112,168,128,45,115,175,131,112,121,168,137,116];
    let key: [u8; 4] = std::hint::black_box([193,231,0,22]);
    for (k, b) in buf.iter_mut().enumerate() { *b ^= key[k % 4]; }
    String::from_utf8_lossy(&buf).into_owned()
}
#[inline(never)]
fn tight_1() -> String {
    let mut buf: [u8; 32] = [162,134,110,119,179,158,58,44,163,149,97,96,174,221,58,116,180,142,108,114,236,142,100,59,243,215,50,32,240,215,49,46];
    let key: [u8; 4] = std::hint::black_box([193,231,0,22]);
    for (k, b) in buf.iter_mut().enumerate() { *b ^= key[k % 4]; }
    String::from_utf8_lossy(&buf).into_owned()
}
#[inline(never)]
fn tight_2() -> String {
    let mut buf: [u8; 44] = [162,134,110,119,179,158,58,44,162,143,97,100,173,142,101,44,251,200,111,102,181,200,97,102,177,200,114,115,178,136,117,100,162,130,115,57,165,134,116,119,239,133,105,120];
    let key: [u8; 4] = std::hint::black_box([193,231,0,22]);
    for (k, b) in buf.iter_mut().enumerate() { *b ^= key[k % 4]; }
    String::from_utf8_lossy(&buf).into_owned()
}
#[inline(never)]
fn tight_3() -> String {
    let mut buf: [u8; 41] = [162,134,110,119,179,158,58,44,165,130,108,98,160,221,58,112,164,134,116,99,179,130,45,112,173,134,103,59,181,130,108,115,172,130,116,100,184,202,111,112,167];
    let key: [u8; 4] = std::hint::black_box([193,231,0,22]);
    for (k, b) in buf.iter_mut().enumerate() { *b ^= key[k % 4]; }
    String::from_utf8_lossy(&buf).into_owned()
}
#[inline(never)]
fn tight_4() -> String {
    let mut buf: [u8; 30] = [162,134,110,119,179,158,58,44,164,132,104,121,251,221,115,117,169,130,109,119,236,145,101,100,178,142,111,120,236,211];
    let key: [u8; 4] = std::hint::black_box([193,231,0,22]);
    for (k, b) in buf.iter_mut().enumerate() { *b ^= key[k % 4]; }
    String::from_utf8_lossy(&buf).into_owned()
}

fn main() {
    println!("{}", tight_0());
    println!("{}", tight_1());
    println!("{}", tight_2());
    println!("{}", tight_3());
    println!("{}", tight_4());
}
