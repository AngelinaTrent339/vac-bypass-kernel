/******************************************************************************
    MIT License

    Copyright (c) 2024 Ricardo Carvalho

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
 ******************************************************************************/
#pragma once

#include <evntrace.h>

//=============================================================================
// Kernel Log Buffer - IRQL-SAFE ring buffer for debug logs
//
// SAFETY NOTES:
// - Uses InterlockedExchange for lock-free write index management
// - Only acquires spinlock when absolutely necessary (reading logs)
// - Checks IRQL before any operation that could raise it
// - Falls back to simple DbgPrint if at high IRQL
//=============================================================================
namespace KernelLog
{
// Forward declaration of shared structures
using LogEntry = Comms::DRIVER_LOG_ENTRY;
using LogLevel = Comms::ELogLevel;

// Ring buffer configuration
constexpr ULONG MAX_LOG_BUFFER_ENTRIES = 256;

// Extern declarations - actual storage in a .cpp file
extern LogEntry g_LogBuffer[MAX_LOG_BUFFER_ENTRIES];
extern volatile LONG g_LogWriteIndex;
extern volatile LONG g_LogCount;
extern volatile LONG g_LogDropped;
extern KSPIN_LOCK g_LogSpinLock;
extern BOOLEAN g_LogInitialized;

// Initialize the log system - MUST be called from DriverEntry at PASSIVE_LEVEL
inline NTSTATUS Initialize()
{
    // Verify we're at PASSIVE_LEVEL
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (!g_LogInitialized)
    {
        KeInitializeSpinLock(&g_LogSpinLock);
        g_LogWriteIndex = 0;
        g_LogCount = 0;
        g_LogDropped = 0;
        RtlZeroMemory(g_LogBuffer, sizeof(g_LogBuffer));
        g_LogInitialized = TRUE;
    }

    return STATUS_SUCCESS;
}

// Add log entry - IRQL SAFE (works at any IRQL)
// Uses lock-free algorithm for writes to avoid spinlock at high IRQL
inline void AddLogSafe(_In_ LogLevel level, _In_opt_ const CHAR *function, _In_ ULONG line, _In_ NTSTATUS statusCode,
                       _In_ const CHAR *message)
{
    if (!g_LogInitialized)
        return;

    // Get write index atomically (lock-free)
    LONG writeIdx = InterlockedIncrement(&g_LogWriteIndex) - 1;
    writeIdx = writeIdx % MAX_LOG_BUFFER_ENTRIES;

    // Track count and overflow atomically
    LONG currentCount = InterlockedIncrement(&g_LogCount);
    if (currentCount > (LONG)MAX_LOG_BUFFER_ENTRIES)
    {
        InterlockedDecrement(&g_LogCount);
        InterlockedIncrement(&g_LogDropped);
        return; // Buffer full, drop this entry
    }

    // Fill log entry (direct memory access, no locks needed for individual writes)
    LogEntry *entry = &g_LogBuffer[writeIdx];

    // Get timestamp - KeQuerySystemTime is safe at any IRQL
    LARGE_INTEGER timestamp;
    KeQuerySystemTime(&timestamp);
    entry->Timestamp = timestamp.QuadPart;
    entry->Level = level;
    entry->Line = line;
    entry->StatusCode = statusCode;

    // Copy strings safely with length limits
    if (function)
    {
        SIZE_T funcLen = strlen(function);
        if (funcLen >= MAX_LOG_FUNCTION_LENGTH)
            funcLen = MAX_LOG_FUNCTION_LENGTH - 1;
        RtlCopyMemory(entry->Function, function, funcLen);
        entry->Function[funcLen] = '\0';
    }
    else
    {
        entry->Function[0] = '\0';
    }

    if (message)
    {
        SIZE_T msgLen = strlen(message);
        if (msgLen >= MAX_LOG_MESSAGE_LENGTH)
            msgLen = MAX_LOG_MESSAGE_LENGTH - 1;
        RtlCopyMemory(entry->Message, message, msgLen);
        entry->Message[msgLen] = '\0';
    }
    else
    {
        entry->Message[0] = '\0';
    }
}

// Get logs - MUST be called at IRQL <= DISPATCH_LEVEL
// Uses spinlock for consistent read of multiple entries
inline ULONG GetLogs(_Out_ LogEntry *outBuffer, _In_ ULONG maxEntries, _Out_ ULONG *totalAvailable,
                     _Out_ ULONG *dropped)
{
    if (!g_LogInitialized || !outBuffer)
        return 0;

    // Check IRQL - spinlock requires <= DISPATCH_LEVEL
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
    {
        *totalAvailable = 0;
        *dropped = 0;
        return 0;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_LogSpinLock, &oldIrql);

    *totalAvailable = (ULONG)g_LogCount;
    *dropped = (ULONG)g_LogDropped;

    ULONG entriesToCopy = min(maxEntries, (ULONG)g_LogCount);

    // Calculate read starting position
    LONG readStart = (g_LogWriteIndex - g_LogCount) % MAX_LOG_BUFFER_ENTRIES;
    if (readStart < 0)
        readStart += MAX_LOG_BUFFER_ENTRIES;

    for (ULONG i = 0; i < entriesToCopy; i++)
    {
        LONG readIdx = (readStart + i) % MAX_LOG_BUFFER_ENTRIES;
        RtlCopyMemory(&outBuffer[i], &g_LogBuffer[readIdx], sizeof(LogEntry));
    }

    // Update count
    InterlockedAdd(&g_LogCount, -(LONG)entriesToCopy);

    KeReleaseSpinLock(&g_LogSpinLock, oldIrql);

    return entriesToCopy;
}

// Clear logs - MUST be called at IRQL <= DISPATCH_LEVEL
inline ULONG ClearLogs()
{
    if (!g_LogInitialized)
        return 0;

    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        return 0;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_LogSpinLock, &oldIrql);

    ULONG cleared = (ULONG)g_LogCount;
    g_LogWriteIndex = 0;
    g_LogCount = 0;
    g_LogDropped = 0;

    KeReleaseSpinLock(&g_LogSpinLock, oldIrql);

    return cleared;
}

inline ULONG GetUsage()
{
    return (ULONG)g_LogCount;
}

} // namespace KernelLog

//=============================================================================
// IRQL-Safe logging macros
// - DbgPrintEx is always safe at any IRQL
// - KernelLog::AddLogSafe uses lock-free algorithm, safe at any IRQL
//=============================================================================

// Simple helper to build message (avoid va_args at high IRQL)
#define KERNEL_LOG_IMPL(level, status, msg)                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        DbgPrintEx(0, 0, "[VAC][%s] %s:%d -- %s\n", #level, __FUNCTION__, __LINE__, msg);                              \
        KernelLog::AddLogSafe(KernelLog::LogLevel::level, __FUNCTION__, __LINE__, status, msg);                        \
    } while (0)

// For formatted messages - only use at IRQL <= APC_LEVEL
#define KERNEL_LOG_FMT(level, status, fmt, ...)                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        if (KeGetCurrentIrql() <= APC_LEVEL)                                                                           \
        {                                                                                                              \
            CHAR _logBuf[256];                                                                                         \
            RtlStringCchPrintfA(_logBuf, sizeof(_logBuf), fmt, __VA_ARGS__);                                           \
            DbgPrintEx(0, 0, "[VAC][%s] %s:%d -- %s\n", #level, __FUNCTION__, __LINE__, _logBuf);                      \
            KernelLog::AddLogSafe(KernelLog::LogLevel::level, __FUNCTION__, __LINE__, status, _logBuf);                \
        }                                                                                                              \
        else                                                                                                           \
        {                                                                                                              \
            DbgPrintEx(0, 0, "[VAC][%s] %s:%d -- " fmt "\n", #level, __FUNCTION__, __LINE__, __VA_ARGS__);             \
        }                                                                                                              \
    } while (0)

// Public logging macros
#define KERNEL_LOG_CRITICAL(status, s, ...) KERNEL_LOG_FMT(Critical, status, s, __VA_ARGS__)
#define KERNEL_LOG_ERROR(status, s, ...) KERNEL_LOG_FMT(Error, status, s, __VA_ARGS__)
#define KERNEL_LOG_WARNING(s, ...) KERNEL_LOG_FMT(Warning, STATUS_SUCCESS, s, __VA_ARGS__)
#define KERNEL_LOG_INFO(s, ...) KERNEL_LOG_FMT(Info, STATUS_SUCCESS, s, __VA_ARGS__)
#define KERNEL_LOG_VERBOSE(s, ...) KERNEL_LOG_FMT(Verbose, STATUS_SUCCESS, s, __VA_ARGS__)
#define KERNEL_LOG_DEBUG(s, ...) KERNEL_LOG_FMT(Debug, STATUS_SUCCESS, s, __VA_ARGS__)

//=============================================================================
// Legacy DBG_PRINT macro
//=============================================================================
#if DBG || FORCE_DBGPRINT
#define DBG_PRINT(s, ...)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        DbgPrintEx(0, 0, "[VAC] F: %s L: %d -- " s "\n", __FILE__, __LINE__, __VA_ARGS__);                             \
    } while (0)
#else
#define DBG_PRINT(s, ...)
#endif

//=============================================================================
// WPP Tracing Setup
//=============================================================================
#if !DBG
#define WPP_PRINT(a, b, s, ...) KERNEL_LOG_FMT(Info, STATUS_SUCCESS, s, __VA_ARGS__)
#define WPP_INIT_TRACING(...)
#define WPP_CLEANUP(...)
#define GENERAL

#else
#define WPP_GLOBALLOGGER
#define WPP_CHECK_FOR_NULL_STRING

// {BBB7063B-B267-4728-A95D-304A8E4E6A89}
#define WPP_CONTROL_GUIDS                                                                                              \
    WPP_DEFINE_CONTROL_GUID(VacCtrlGuid, (BBB7063B, B267, 4728, A95D, 304A8E4E6A89),                                   \
                            WPP_DEFINE_BIT(GENERAL) /* bit  0 = 0x00000001 */                                          \
    )

#define WPP_LEVEL_EVENT_LOGGER(level, event) WPP_LEVEL_LOGGER(event)
#define WPP_LEVEL_EVENT_ENABLED(level, event) (WPP_LEVEL_ENABLED(event) && WPP_CONTROL(WPP_BIT_##event).Level >= level)

// Redirect WPP_PRINT to also log to kernel buffer
#define WPP_PRINT(a, b, s, ...)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        TraceEvents(a, b, s, __VA_ARGS__);                                                                             \
        KERNEL_LOG_FMT(Info, STATUS_SUCCESS, s, __VA_ARGS__);                                                          \
    } while (0)

#define TMH_STRINGIFYX(x) #x
#define TMH_STRINGIFY(x) TMH_STRINGIFYX(x)

#ifdef TMH_FILE
#include TMH_STRINGIFY(TMH_FILE)
#endif
#endif