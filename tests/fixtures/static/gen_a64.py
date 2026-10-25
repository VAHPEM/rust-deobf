import sys
mode = sys.argv[1]   # zerokey | shortkey | stack
L = [".text", ".globl _start"]
if mode in ("zerokey", "shortkey"):
    pts = [b"configuration-endpoint-alpha", b"telemetry-settings-path-bravo", b"resource-data-file-charlie"]
    key = bytes(16) if mode == "zerokey" else bytes(range(0x41, 0x45))
    full = bytes(16) if mode == "zerokey" else bytes(range(0x41, 0x51))
    L += ["dec:", "  mov x3, #0", "1:", "  ldrb w9, [x1, x3]", "  and x10, x3, #0xf",
          "  adrp x11, key", "  add x11, x11, :lo12:key", "  ldrb w12, [x11, x10]",
          "  eor w9, w9, w12", "  strb w9, [x0, x3]", "  add x3, x3, #1", "  cmp x3, x2",
          "  b.lo 1b", "  ret", "_start:"]
    for n, p in enumerate(pts):
        L += ["  adrp x0, outbuf", "  add x0, x0, :lo12:outbuf", f"  adrp x1, ct{n}",
              f"  add x1, x1, :lo12:ct{n}", f"  mov w2, #{len(p)}", "  bl dec"]
    L += ["  mov x8, #93", "  svc #0", ".section .rodata"]
    for n, p in enumerate(pts):
        L += [f"ct{n}: .byte " + ",".join(str(c ^ full[i % 16]) for i, c in enumerate(p))]
    L += [".section .keysec,\"a\"", "key: .byte " + ",".join(map(str, key)), ".bss", "outbuf: .skip 256"]
else:
    L += ["_start:", "  sub sp, sp, #64"]
    s = b"hello world!"
    for k in range(0, 12, 4):
        w = int.from_bytes(s[k:k+4], "little")
        L += [f"  mov w8, #{w & 0xffff}", f"  movk w8, #{w >> 16}, lsl #16", f"  str w8, [sp, #{k}]"]
    for k, ch in enumerate(b"telemetry-config"):
        L += [f"  mov w9, #{ch}", f"  ldrb w9, [x0, #{k}]", f"  strb w9, [sp, #{32 + k}]"]
    L += ["  add sp, sp, #64", "  ret"]
print("\n".join(L))
