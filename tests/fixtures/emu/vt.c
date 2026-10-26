static void dropf(void) {}
static void m1(void) {}
struct vt { void (*drop)(void); unsigned size, align; void (*m)(void); };
const struct vt VT = { dropf, 12, 4, m1 };   /* Rust-like vtable: ptr, size, align, method */
const struct vt * volatile G = &VT;
unsigned get_size(void) { return G->size; }
void _start(void) { for(;;); }
