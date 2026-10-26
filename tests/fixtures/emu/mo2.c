volatile int MARK;
__attribute__((constructor)) static void ctor(void) { MARK = 0x1337; }
int main(void) { return MARK; }
