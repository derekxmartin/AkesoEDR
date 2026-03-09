/*
 * sentinel-drv/main.c
 * Kernel-mode WDM driver entry point (stub).
 *
 * This file will contain DriverEntry and DriverUnload once Phase 1 begins.
 * For now it serves as a compilation placeholder.
 */

#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#endif

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();
}
