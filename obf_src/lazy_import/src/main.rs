// Benign "lazy import" shape (VALIDATION §81): the names of two harmless Win32 APIs (the tick
// count, the current processor number) are XOR-encoded, decoded at run time and resolved with
// GetModuleHandleA + GetProcAddress, so neither appears in the import table. On other targets the
// names are only decoded and printed.
const K: u8 = 0x4b;
static MODULE: [u8; 12] = [32,46,57,37,46,39,120,121,101,47,39,39];
static API1: [u8; 12] = [12,46,63,31,34,40,32,8,36,62,37,63];
static API2: [u8; 25] = [12,46,63,8,62,57,57,46,37,63,27,57,36,40,46,56,56,36,57,5,62,38,41,46,57];

#[inline(never)]
fn dec(b: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = b.iter().map(|c| c ^ K).collect();
    v.push(0);
    v
}

#[cfg(windows)]
mod win {
    extern "system" {
        pub fn GetModuleHandleA(name: *const u8) -> *mut u8;
        pub fn GetProcAddress(module: *mut u8, name: *const u8) -> *mut u8;
    }
}

fn main() {
    let m = dec(&MODULE);
    for enc in [&API1[..], &API2[..]] {
        let name = dec(enc);
        #[cfg(windows)]
        unsafe {
            let p = win::GetProcAddress(win::GetModuleHandleA(m.as_ptr()), name.as_ptr());
            if !p.is_null() {
                let f: extern "system" fn() -> u32 = std::mem::transmute(p);
                println!("{} -> {}", String::from_utf8_lossy(&name[..name.len() - 1]), f());
                continue;
            }
        }
        println!("{}", String::from_utf8_lossy(&name[..name.len() - 1]));
    }
    let _ = &m;
}
