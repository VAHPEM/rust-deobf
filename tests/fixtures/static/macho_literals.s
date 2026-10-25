.section __TEXT,__text
.globl _main
_main:
  adrp x0, _tbl@PAGE
  add x0, x0, _tbl@PAGEOFF
  ret
.section __TEXT,__const
_s1: .ascii "alpha-literal-onebravo-literal-two"
.section __DATA,__const
.p2align 3
_tbl:
  .quad _s1
  .quad 17
  .quad _s1+17
  .quad 17
