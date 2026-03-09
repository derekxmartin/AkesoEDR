/*
 * sentinel-agent/main.cpp
 * User-mode agent service entry point (stub).
 *
 * Will become a Windows service in Phase 4.
 * For now, a minimal main() to validate the build.
 */

#include <windows.h>
#include <cstdio>

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    std::printf("SentinelPOC Agent v1.0.0 (stub)\n");
    return 0;
}
