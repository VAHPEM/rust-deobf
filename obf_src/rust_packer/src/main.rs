// Benign "Rust-written packer" shape (VALIDATION §83): the stage-2 is RC4-encrypted inside the
// binary; at run time the stub (a full Rust program with std) allocates a fresh read/write/execute
// region, decrypts the stage-2 into it and calls it. The stage-2 does nothing but return 42 (a
// NOP sled, then `mov eax, 42; ret` / `mov w0, #42; ret`; 64 bytes). Exists to be EMULATED by
// unpack_emulate.py; it is safe to run as well. No crates; the allocation is the platform's own (mmap / VirtualAlloc).
const KEY: &[u8] = b"rust-deobf-bench-pack";
#[cfg(target_arch = "x86_64")]
static STAGE2: [u8; 64] = [153,116,37,253,126,215,33,77,190,133,104,114,118,96,179,201,6,16,193,220,217,224,162,205,252,17,224,123,27,150,70,112,139,85,26,63,154,183,3,87,18,58,236,17,112,163,212,186,124,21,122,71,134,2,71,95,175,190,74,223,5,216,185,228];
#[cfg(target_arch = "aarch64")]
static STAGE2: [u8; 64] = [22,196,182,184,241,103,178,8,49,53,251,55,249,208,32,140,137,160,82,153,86,80,49,136,115,161,115,62,148,38,213,53,4,229,137,122,21,7,144,18,157,138,127,84,255,19,71,255,243,165,233,2,9,178,212,26,127,43,114,167,197,219,230,241];
#[cfg(target_arch = "x86")]
static STAGE2: [u8; 64] = [153,116,37,253,126,215,33,77,190,133,104,114,118,96,179,201,6,16,193,220,217,224,162,205,252,17,224,123,27,150,70,112,139,85,26,63,154,183,3,87,18,58,236,17,112,163,212,186,124,21,122,71,134,2,71,95,175,190,74,223,5,216,185,228];

#[inline(never)]
fn rc4(key: &[u8], data: &mut [u8]) {
    let mut s: [u8; 256] = [0; 256];
    for (i, v) in s.iter_mut().enumerate() { *v = i as u8; }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    for b in data.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        *b ^= s[s[i as usize].wrapping_add(s[j as usize]) as usize];
    }
}

#[cfg(unix)]
unsafe fn alloc_rwx(n: usize) -> *mut u8 {
    extern "C" { fn mmap(a: *mut u8, n: usize, p: i32, f: i32, fd: i32, o: i64) -> *mut u8; }
    // PROT_READ|WRITE|EXEC, MAP_PRIVATE|MAP_ANONYMOUS (Linux values)
    mmap(std::ptr::null_mut(), n, 7, 0x22, -1, 0)
}

#[cfg(windows)]
unsafe fn alloc_rwx(n: usize) -> *mut u8 {
    extern "system" { fn VirtualAlloc(a: *mut u8, n: usize, t: u32, p: u32) -> *mut u8; }
    VirtualAlloc(std::ptr::null_mut(), n, 0x3000, 0x40)   // MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
}

fn main() {
    let mut buf = STAGE2;
    rc4(KEY, &mut buf);
    unsafe {
        let p = alloc_rwx(4096);
        if p.is_null() || p as isize == -1 { println!("no memory"); return; }
        std::ptr::copy_nonoverlapping(buf.as_ptr(), p, buf.len());
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("dc cvau, {0}", "dsb ish", "ic ivau, {0}", "dsb ish", "isb", in(reg) p);
        let f: extern "C" fn() -> u32 = std::mem::transmute(p);
        println!("stage-2 returned {}", f());
    }
}
