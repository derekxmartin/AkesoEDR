/*
 * sentinel-hook/main.c
 * User-mode hooking DLL entry point (stub).
 *
 * Injected into target processes via KAPC (Phase 2).
 * Installs inline hooks on ntdll functions (Phase 3).
 */

#include <windows.h>
#include "telemetry.h"

BOOL APIENTRY
DllMain(
    HMODULE hModule,
    DWORD   dwReason,
    LPVOID  lpReserved
)
{
    (void)hModule;
    (void)lpReserved;

    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}
