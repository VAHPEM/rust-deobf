import sys
mode = sys.argv[1]   # "shortkey" | "slice_rcx" | "slice_r9"
key_full = bytes(range(0x41, 0x51))       # 16-byte key
pts = [b"configuration-endpoint-alpha", b"telemetry-settings-path-bravo", b"resource-data-file-charlie"]
def enc(p, key): return bytes(c ^ key[i % len(key)] for i, c in enumerate(p))
key = key_full if mode != "shortkey" else key_full[:4]
L = [".intel_syntax noprefix", ".text", ".globl _start", "_start:"]
for n, p in enumerate(pts):
    if mode == "shortkey":
        L += [f"  lea rdi,[rip+outbuf]", f"  lea rsi,[rip+ct{n}]", f"  mov edx,{len(p)}", "  call dec"]
    else:
        reg32, reg64 = ("ecx", "rcx") if mode == "slice_rcx" else ("r9d", "r9")
        L += ["  sub rsp,0x40", f"  lea rax,[rip+ct{n}]", "  mov [rsp+0x10],rax",
              f"  mov {reg32},{len(p)}", f"  mov [rsp+0x18],{reg64}",
              "  lea rdi,[rip+outbuf]", "  lea rsi,[rsp+0x10]", "  call dec", "  add rsp,0x40"]
L += ["  mov eax,60", "  xor edi,edi", "  syscall",
      "dec:", "  push rbp", "  mov rbp,rsp", "  xor ecx,ecx", ".Lloop:",
      "  movzx eax, byte ptr [rsi+rcx]", "  mov r8, rcx", "  and r8d, 0xf",
      "  lea r9,[rip+key]", "  xor al, byte ptr [r9+r8]", "  mov [rdi+rcx], al",
      "  inc rcx", "  cmp rcx, rdx", "  jb .Lloop", "  pop rbp", "  ret"]
L += [".section .rodata"]
for n, p in enumerate(pts):
    L += [f"ct{n}: .byte " + ",".join(str(b) for b in enc(p, key_full))]
L += [".section .keysec,\"a\"", "key: .byte " + ",".join(str(b) for b in key)]
L += [".bss", "outbuf: .skip 256"]
print("\n".join(L))
