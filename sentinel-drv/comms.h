/*
 * sentinel-drv/comms.h
 * Filter communication port interface for driver → agent telemetry.
 *
 * The communication port is built on FltCreateCommunicationPort (minifilter
 * framework). The agent connects from user-mode via FilterConnectCommunicationPort.
 *
 * Functions:
 *   SentinelCommsInit  — Create the communication port (called from DriverEntry)
 *   SentinelCommsStop  — Close the port and disconnect clients (called from unload)
 *   SentinelCommsSend  — Send a telemetry event to the connected agent
 *
 * IRQL: All functions run at PASSIVE_LEVEL unless noted.
 */

#ifndef SENTINEL_COMMS_H
#define SENTINEL_COMMS_H

#include <fltKernel.h>
#include "telemetry.h"

/* ── Public API ──────────────────────────────────────────────────────────── */

/*
 * Initialize the filter communication port.
 * Must be called after FltRegisterFilter succeeds.
 */
NTSTATUS
SentinelCommsInit(
    _In_ PFLT_FILTER Filter
);

/*
 * Tear down the communication port and disconnect any connected client.
 * Safe to call if SentinelCommsInit was never called or already stopped.
 */
VOID
SentinelCommsStop(VOID);

/*
 * Send a SENTINEL_EVENT to the connected agent.
 * If no agent is connected, the event is silently dropped.
 *
 * IRQL: <= APC_LEVEL (FltSendMessage requirement)
 *
 * Returns:
 *   STATUS_SUCCESS          — event sent
 *   STATUS_PORT_DISCONNECTED — no agent connected (event dropped)
 *   Other NTSTATUS          — send failure
 */
NTSTATUS
SentinelCommsSend(
    _In_ const SENTINEL_EVENT* Event
);

/*
 * Check whether an agent is currently connected.
 */
BOOLEAN
SentinelCommsIsConnected(VOID);

#endif /* SENTINEL_COMMS_H */
