/* two imported calls with an undecodable byte (0xd6 is invalid in 64-bit mode) placed in .text
   ahead of them: a linear sweep that stops at the first bad byte binds none of the call sites */
__declspec(dllimport) unsigned GetTickCount(void);
__declspec(dllimport) void Sleep(unsigned);
__asm__(".text\n.byte 0xd6, 0x06\n");
int a(void) { return GetTickCount(); }
void b(void) { Sleep(1); }
void entry(void) { a(); b(); }
