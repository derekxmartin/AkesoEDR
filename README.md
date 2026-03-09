# SentinelPOC

A proof-of-concept Endpoint Detection & Response (EDR) agent for Windows x64.

Architecture derived from sensor models in *Evading EDR* by Matt Hand (No Starch Press, 2023).

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| `sentinel-drv` | C17 (WDK) | Kernel-mode WDM driver: process/thread callbacks, object notifications, image-load, registry, minifilter, WFP callout |
| `sentinel-hook` | C17 | User-mode hooking DLL injected via KAPC. Inline hooks on ntdll functions for API call telemetry |
| `sentinel-agent` | C++20 | User-mode Windows service. Event aggregation, rule engine, ETW consumer, AMSI provider, scanner |
| `sentinel-cli` | C++20 | Console management tool for querying agent state and triggering actions |

## Building

### Prerequisites

- Visual Studio 2022 with C++ desktop workload
- CMake 3.20+
- Windows Driver Kit (WDK) -- required for kernel driver, optional for user-mode only builds

### Configure & Build

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

If WDK is not installed, the kernel driver (`sentinel-drv`) is skipped automatically.

### Test Signing (for driver deployment)

```powershell
.\scripts\setup-testsigning.ps1
```

## Project Structure

```
CMakeLists.txt          Top-level CMake
common/                 Shared headers (telemetry, IPC, constants)
sentinel-drv/           Kernel-mode driver
sentinel-hook/          User-mode hooking DLL
sentinel-agent/         Agent Windows service
sentinel-cli/           CLI management tool
rules/                  YAML detection rules
yara-rules/             YARA rule files
tests/                  Integration tests
scripts/                Build/install helpers
docs/                   Documentation
```

## Status

Phase 0 -- Project scaffolding complete. See `REQUIREMENTS.md` for the full implementation roadmap.

## License

MIT License. See [LICENSE](LICENSE).

## Disclaimer

This is an educational proof-of-concept. It is not production security software. Use only in authorized test environments.
