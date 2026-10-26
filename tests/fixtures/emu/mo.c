static int f1(void) { return 1; }
static int f2(void) { return 2; }
int (*const TABLE[2])(void) = { f1, f2 };
int call1(void) { return TABLE[1](); }
__attribute__((constructor)) static void ctor(void) { }
int main(void) { return call1(); }
