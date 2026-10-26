const char *volatile KEYPTR;
char key[16] = "SECRET-KEY-1234";     /* initialised .data */
char big[0x4000];                       /* zero-init: merged into .data by lld-link */
const char *get(void) { return key; }
int mainCRTStartup(void) { big[1] = key[0]; return 0; }
