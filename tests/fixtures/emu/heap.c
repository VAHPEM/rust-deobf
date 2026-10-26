void *malloc(unsigned long);
char *volatile CONFIG;                      /* filled by a constructor (lazy config / anti-emu marker) */
__attribute__((constructor)) static void init(void) {
    CONFIG = malloc(16);
    for (int i = 0; i < 8; i++) CONFIG[i] = 'K';   /* key material "KKKKKKKK" */
}
char *g2;
char *later(void) {                         /* an ordinary function emulated in the sweep */
    char *p = malloc(16);
    for (int i = 0; i < 8; i++) p[i] = 'z';
    g2 = p;
    return CONFIG;                          /* should still see "KKKKKKKK" */
}
