void (*volatile HOOK)(void);                       /* never set: 0 */
__attribute__((noinline)) void notify(void) { HOOK(); }
static const unsigned char A[] = {0x39,0x3f,0x39,0x34,0x3f,0x2e,0x77,0x6b,0x00};   /* ^0x5a */
static const unsigned char B[] = {0x39,0x3f,0x39,0x34,0x3f,0x2e,0x77,0x68,0x00};
char outa[16], outb[16];
__attribute__((noinline)) void work(void) {
    for (int i = 0; A[i]; i++) outa[i] = A[i] ^ 0x5a ^ 0x5a ^ 0x5a;
    notify();                                       /* a callee that calls a null pointer */
    for (int i = 0; B[i]; i++) outb[i] = B[i] ^ 0x5a ^ 0x5a ^ 0x5a;
}
void _start(void) { work(); for(;;); }
