/* a 32-byte initial-exec thread-local next to an 8-byte one: with a fixed 8-byte offset stride the
   struct overlaps its neighbour, so writing T2 clobbers a field of T1 and f() no longer returns
   4 * 0x1111 = 0x4444 */
struct big { long a, b, c, d; };
__attribute__((tls_model("initial-exec"))) __thread volatile struct big T1;
__attribute__((tls_model("initial-exec"))) __thread volatile long T2;
long f(void) {
    T1.a = T1.b = T1.c = T1.d = 0x1111;
    T2 = 0x2222;
    return T1.a + T1.b + T1.c + T1.d;
}
