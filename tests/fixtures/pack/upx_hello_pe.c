/* benign fixture: a tiny console program that reads an env var, the tick count and the size of
   its own executable, then prints them. Built with mingw and packed with UPX to give a real
   packed PE (UPX stub + compressed stage-2 + import rebuild via LoadLibraryA/GetProcAddress). */
#include <windows.h>
#include <stdio.h>
int main(void) {
    char buf[64] = {0};
    DWORD n = GetEnvironmentVariableA("RUST_DEOBF_FIXTURE", buf, sizeof buf);
    DWORD t = GetTickCount();
    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);
    HANDLE h = CreateFileA(self, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD sz = (h != INVALID_HANDLE_VALUE) ? GetFileSize(h, NULL) : 0;
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    printf("fixture-ok env=%lu tick=%lu size=%lu\n", (unsigned long)n, (unsigned long)(t & 1), (unsigned long)sz);
    return 0;
}
