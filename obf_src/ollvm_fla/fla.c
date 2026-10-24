/* A function control-flow-flattened in the classic OLLVM `-fla` shape: a switch-variable, a
 * dispatcher loop, and cases that transition by assigning the next state constant DIRECTLY
 * (next = const), which is how OLLVM differs from goldberg's XOR-delta transitions. Hand-written
 * in the post-`-fla` form and compiled with a real compiler (clang) so the binary carries real
 * codegen idioms; it exercises the deflattener's direct-assignment path, which goldberg (XOR) does
 * not. The original logic decodes a canary string one byte at a time across several states, with a
 * real branch (length parity) kept as a case with two outgoing states.
 *
 * Original (unflattened) logic:
 *     buf[i] = ct[i] ^ KEY[i % 4]  for i in 0..len
 *     if (len & 1) buf[len-1] ^= 0x20;   // a real branch that survives flattening
 */
#include <stdio.h>
#include <string.h>

static const unsigned char KEY[4] = {0x5a, 0x31, 0x7e, 0x14};
/* "ollvm::canary::flatten-demo-7c3f" xored with KEY (len 32) */
static unsigned char CT[33];
static void init_ct(void) {
    const char *p = "ollvm::canary::flatten-demo-7c3f";
    int n = (int)strlen(p);
    for (int i = 0; i < n; i++) CT[i] = (unsigned char)p[i] ^ KEY[i & 3];
    CT[n] = 0;
}

__attribute__((noinline))
void decode(char *out, const unsigned char *ct, int len) {
    int i = 0;
    unsigned int sv = 0x1a2b3c4du;        /* switch variable, start state */
    while (1) {
        switch (sv) {
            case 0x1a2b3c4du:             /* entry: init */
                i = 0;
                sv = 0x7f55aa01u;         /* -> loop-head (direct assignment) */
                break;
            case 0x7f55aa01u:             /* loop head: i < len ? */
                if (i < len) sv = 0x33cc9920u;   /* -> body */
                else sv = 0x60ded00fu;           /* -> tail check (real branch, two next states) */
                break;
            case 0x33cc9920u:             /* body: out[i] = ct[i] ^ KEY[i%4]; i++ */
                out[i] = (char)(ct[i] ^ KEY[i & 3]);
                i++;
                sv = 0x7f55aa01u;         /* -> loop head */
                break;
            case 0x60ded00fu:             /* tail: parity branch */
                if (len & 1) sv = 0x0a0b0c0du;   /* odd -> flip */
                else sv = 0xdeadbeefu;           /* even -> done */
                break;
            case 0x0a0b0c0du:             /* flip last byte */
                out[len - 1] = (char)(out[len - 1] ^ 0x20);
                sv = 0xdeadbeefu;         /* -> done */
                break;
            case 0xdeadbeefu:             /* terminal */
                out[len] = 0;
                return;
        }
    }
}

int main(void) {
    init_ct();
    char out[33];
    decode(out, CT, 32);
    printf("%s\n", out);
    return 0;
}
