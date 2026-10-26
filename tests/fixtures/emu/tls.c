__thread volatile int ta, tb;
int f(void) { ta = 0x1111; tb = 0x2222; return ta; }
