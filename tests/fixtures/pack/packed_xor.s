# A tiny, benign, freestanding "packed" ELF: entry (_start) is an in-place XOR unpack stub that
# decodes a 24-byte stage-2 (NOP sled + ret) into a .bss buffer and jumps to it. Never run for
# real (jumps into .bss); it exists only to be *emulated* by unpack_emulate.py. Key = 0x5a.
.intel_syntax noprefix
.section .text
.globl _start
_start:
    lea rsi, [rip+enc]
    lea rdi, [rip+dest]
    mov rcx, 24
.Lloop:
    mov al, [rsi]
    xor al, 0x5a
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jnz .Lloop
    lea rax, [rip+dest]
    jmp rax

.section .data
enc:
    # 23 * NOP (0x90) then RET (0xc3), each XOR 0x5a  ->  0x90^0x5a=0xca, 0xc3^0x5a=0x99
    .fill 23, 1, 0xca
    .byte 0x99
.section .bss
dest:
    .space 64
