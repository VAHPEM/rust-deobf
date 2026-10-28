/* a constructor sets a global in an image whose .bss (a 32 MB static arena) exceeds the emulator's
   16 MB _BSS_CAP: the primed baseline must still keep MARK = 0x1337 after a reset */
volatile int MARK;
char BIG[32 << 20];
__attribute__((constructor)) static void ctor(void) { MARK = 0x1337; }
int get(void) { return MARK + BIG[0]; }
void _start(void) { for (;;) ; }
