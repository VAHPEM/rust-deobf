/* OLLVM -bcf shape, hand-written in its post-pass form: every real block is guarded by an opaque
 * predicate over two globals the program never writes (OLLVM's x / y), whose false side leads to a
 * bogus clone that never runs. y < 10 || x*(x-1) is even: always true (the product of two
 * consecutive integers is even), whatever x and y hold. */
#include <stdio.h>
int x, y;                     /* OLLVM: zero-initialised globals, never written */
__attribute__((noinline)) int junk(int v) { return v * 7 + 3; }
__attribute__((noinline)) int step(int v) {
    if (y < 10 || ((x * (x - 1)) % 2) == 0) v = v * 3 + 1; else v = junk(v);
    if (((x * (x - 1)) & 1) == 0) v ^= 0x55; else v = junk(v ^ 1);
    if (((x * (x + 1)) % 2) != 0) v = junk(v + 2); else v += 9;
    return v;
}
int main(int argc, char **argv) { (void)argv; printf("%d\n", step(argc)); return 0; }
