/*
 * sentinel-drv/callbacks_process.c
 * Process creation/termination callback — PsSetCreateProcessNotifyRoutineEx.
 *
 * On every process create/terminate on the system, this callback:
 *   1. Populates a SENTINEL_EVENT with process metadata
 *   2. Extracts token info (user SID, integrity level, elevation)
 *   3. Sends the event to the agent over the filter communication port
 *
 * IRQL: The callback runs at PASSIVE_LEVEL (guaranteed by the OS).
 *
 * Book reference: Chapter 3 — Process- and Thread-Creation Notifications.
 */

#include <fltKernel.h>
#include <ntstrsafe.h>

#include "constants.h"
#include "telemetry.h"
#include "comms.h"
#include "callbacks_process.h"

/* ── Undocumented/missing kernel API declarations ─────────────────────────── */

NTKERNELAPI
HANDLE
PsGetProcessInheritedFromUniqueProcessId(
    _In_ PEPROCESS Process
);

NTKERNELAPI
NTSTATUS
PsGetProcessSessionId(
    _In_  PEPROCESS Process,
    _Out_ PULONG    SessionId
);

/* ── Forward declarations ────────────────────────────────────────────────── */

static VOID
SentinelProcessNotifyCallback(
    _Inout_  PEPROCESS              Process,
    _In_     HANDLE                 ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

static VOID
SentinelFillProcessContext(
    _Out_    SENTINEL_PROCESS_CTX*  Ctx,
    _In_     PEPROCESS              Process,
    _In_     HANDLE                 ProcessId
);

static VOID
SentinelExtractTokenInfo(
    _In_     PEPROCESS              Process,
    _Out_    WCHAR*                 SidBuffer,
    _In_     ULONG                  SidBufferLen,
    _Out_    ULONG*                 IntegrityLevel,
    _Out_    BOOLEAN*               IsElevated
);

static VOID
SentinelSidToString(
    _In_     PSID                   Sid,
    _Out_    WCHAR*                 Buffer,
    _In_     ULONG                  BufferLen
);

/* ── Section placement ───────────────────────────────────────────────────── */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SentinelProcessCallbackInit)
#pragma alloc_text(PAGE, SentinelProcessCallbackStop)
#endif

/* ── State ───────────────────────────────────────────────────────────────── */

static BOOLEAN g_ProcessCallbackRegistered = FALSE;

/* ── Public API ──────────────────────────────────────────────────────────── */

NTSTATUS
SentinelProcessCallbackInit(VOID)
{
    NTSTATUS status;

    PAGED_CODE();

    if (g_ProcessCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateProcessNotifyRoutineEx(
        SentinelProcessNotifyCallback,
        FALSE   /* Remove = FALSE → register */
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelPOC: PsSetCreateProcessNotifyRoutineEx failed 0x%08X\n", status));
        return status;
    }

    g_ProcessCallbackRegistered = TRUE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelPOC: Process creation callback registered\n"));

    return STATUS_SUCCESS;
}

VOID
SentinelProcessCallbackStop(VOID)
{
    PAGED_CODE();

    if (!g_ProcessCallbackRegistered) {
        return;
    }

    PsSetCreateProcessNotifyRoutineEx(
        SentinelProcessNotifyCallback,
        TRUE    /* Remove = TRUE → unregister */
    );

    g_ProcessCallbackRegistered = FALSE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelPOC: Process creation callback unregistered\n"));
}

/* ── Callback implementation ─────────────────────────────────────────────── */

/*
 * PsSetCreateProcessNotifyRoutineEx callback.
 *
 * CreateInfo != NULL → process is being created
 * CreateInfo == NULL → process is terminating
 */
static VOID
SentinelProcessNotifyCallback(
    _Inout_  PEPROCESS              Process,
    _In_     HANDLE                 ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    /*
     * STUB: Minimal callback to isolate BSOD cause.
     * If this stub doesn't crash, the bug is in the callback body above.
     * Re-enable the full implementation once stability is confirmed.
     */
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "SentinelPOC: [STUB] Process CREATE PID=%lu\n",
            (ULONG)(ULONG_PTR)ProcessId));
    } else {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "SentinelPOC: [STUB] Process EXIT PID=%lu\n",
            (ULONG)(ULONG_PTR)ProcessId));
    }
}

/* ── Helper: fill process context ─────────────────────────────────────────── */

static VOID
SentinelFillProcessContext(
    _Out_    SENTINEL_PROCESS_CTX*  Ctx,
    _In_     PEPROCESS              Process,
    _In_     HANDLE                 ProcessId
)
{
    PUNICODE_STRING imageName = NULL;

    Ctx->ProcessId       = (ULONG)(ULONG_PTR)ProcessId;
    Ctx->ParentProcessId = (ULONG)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(Process);
    Ctx->ThreadId        = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    {
        ULONG sessionId = 0;
        NTSTATUS sessionStatus = PsGetProcessSessionId(Process, &sessionId);
        Ctx->SessionId = NT_SUCCESS(sessionStatus) ? sessionId : 0;
    }

    KeQuerySystemTimePrecise(&Ctx->ProcessCreateTime);

    /* Get the image file name */
    if (NT_SUCCESS(SeLocateProcessImageName(Process, &imageName))) {
        if (imageName && imageName->Buffer && imageName->Length > 0) {
            RtlStringCchCopyNW(
                Ctx->ImagePath,
                SENTINEL_MAX_PATH,
                imageName->Buffer,
                imageName->Length / sizeof(WCHAR)
            );
        }
        if (imageName) {
            ExFreePool(imageName);
        }
    }

    /* Token info for the process context */
    SentinelExtractTokenInfo(
        Process,
        Ctx->UserSid,
        SENTINEL_MAX_SID_STRING,
        &Ctx->IntegrityLevel,
        &Ctx->IsElevated
    );
}

/* ── Helper: extract token info ───────────────────────────────────────────── */

/*
 * Opens the process token and extracts:
 *   - User SID (converted to string)
 *   - Integrity level (SECURITY_MANDATORY_*_RID)
 *   - Whether the token is elevated
 */
static VOID
SentinelExtractTokenInfo(
    _In_     PEPROCESS              Process,
    _Out_    WCHAR*                 SidBuffer,
    _In_     ULONG                  SidBufferLen,
    _Out_    ULONG*                 IntegrityLevel,
    _Out_    BOOLEAN*               IsElevated
)
{
    NTSTATUS            status;
    PACCESS_TOKEN       token = NULL;
    PTOKEN_USER         tokenUser = NULL;

    /* Defaults */
    SidBuffer[0] = L'\0';
    *IntegrityLevel = 0;
    *IsElevated = FALSE;

    /* Reference the process token */
    token = PsReferencePrimaryToken(Process);
    if (!token) {
        return;
    }

    /* ── User SID ─────────────────────────────────────────────────────── */

    status = SeQueryInformationToken(token, TokenUser, (PVOID*)&tokenUser);
    if (NT_SUCCESS(status) && tokenUser) {
        SentinelSidToString(
            tokenUser->User.Sid,
            SidBuffer,
            SidBufferLen
        );
        ExFreePool(tokenUser);
    }

    /* ── Integrity level ──────────────────────────────────────────────── */

    {
        PTOKEN_MANDATORY_LABEL label = NULL;

        status = SeQueryInformationToken(
            token, TokenIntegrityLevel, (PVOID*)&label
        );

        if (NT_SUCCESS(status) && label) {
            PSID sid = label->Label.Sid;
            if (sid && RtlValidSid(sid)) {
                ULONG subAuthCount = *RtlSubAuthorityCountSid(sid);
                if (subAuthCount > 0) {
                    *IntegrityLevel = *RtlSubAuthoritySid(sid, subAuthCount - 1);
                }
            }
            ExFreePool(label);
        }
    }

    /* ── Elevation ────────────────────────────────────────────────────── */

    {
        PTOKEN_ELEVATION pElevation = NULL;

        status = SeQueryInformationToken(
            token, TokenElevation, (PVOID*)&pElevation
        );

        if (NT_SUCCESS(status) && pElevation) {
            *IsElevated = (pElevation->TokenIsElevated != 0);
            ExFreePool(pElevation);
        }
    }

    PsDereferencePrimaryToken(token);
}

/* ── Helper: SID to string ────────────────────────────────────────────────── */

/*
 * Convert a SID to its string representation (S-1-5-21-...).
 * We build it manually since RtlConvertSidToUnicodeString allocates
 * and we want to write directly into a fixed buffer.
 */
static VOID
SentinelSidToString(
    _In_     PSID                   Sid,
    _Out_    WCHAR*                 Buffer,
    _In_     ULONG                  BufferLen
)
{
    UNICODE_STRING sidString = { 0 };
    NTSTATUS status;

    Buffer[0] = L'\0';

    status = RtlConvertSidToUnicodeString(&sidString, Sid, TRUE);
    if (NT_SUCCESS(status)) {
        RtlStringCchCopyNW(
            Buffer,
            BufferLen,
            sidString.Buffer,
            sidString.Length / sizeof(WCHAR)
        );
        RtlFreeUnicodeString(&sidString);
    }
}
