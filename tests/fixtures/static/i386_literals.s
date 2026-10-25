.code32
.section .rodata
s0: .ascii "alpha-literal-one"
s1: .ascii "bravo-literal-two"
.section .data
.align 4
tbl:
  .long s0
  .long 17
  .long s1
  .long 17
.section .text
.globl _start
_start:
  mov $1, %eax
  int $0x80
