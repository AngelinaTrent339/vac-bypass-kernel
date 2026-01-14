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

#define VAC_DEVICE_GUID L"{272C5244-95ED-402D-B511-CE6511F96DFE}"

#define IOCTL_VAC_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

namespace Comms
{

//=============================================================================
// Log Level definitions (matching WPP trace levels)
//=============================================================================
enum class ELogLevel : UCHAR
{
    Critical = 1, // TRACE_LEVEL_CRITICAL
    Error = 2,    // TRACE_LEVEL_ERROR
    Warning = 3,  // TRACE_LEVEL_WARNING
    Info = 4,     // TRACE_LEVEL_INFORMATION
    Verbose = 5,  // TRACE_LEVEL_VERBOSE
    Debug = 6     // Custom debug level
};

//=============================================================================
// Log Entry structure - single log message from kernel
//=============================================================================
#define MAX_LOG_MESSAGE_LENGTH 256
#define MAX_LOG_FUNCTION_LENGTH 64
#define MAX_LOG_ENTRIES 128

#pragma pack(push, 1)
typedef struct _DRIVER_LOG_ENTRY
{
    ULONG64 Timestamp;                      // Kernel timestamp (KeQuerySystemTime)
    ELogLevel Level;                        // Log level
    ULONG Line;                             // Source line number
    NTSTATUS StatusCode;                    // Associated NTSTATUS (if any)
    CHAR Function[MAX_LOG_FUNCTION_LENGTH]; // Function name
    CHAR Message[MAX_LOG_MESSAGE_LENGTH];   // Log message

    _DRIVER_LOG_ENTRY()
    {
        Timestamp = 0;
        Level = ELogLevel::Info;
        Line = 0;
        StatusCode = 0;
        Function[0] = '\0';
        Message[0] = '\0';
    }

} DRIVER_LOG_ENTRY, *PDRIVER_LOG_ENTRY;
#pragma pack(pop)

//=============================================================================
// Driver Communication Request Types
//=============================================================================
enum class EDriverCommunicationRequest : int
{
    Invalid,
    EnableBypass,
    DisableBypass,
    InjectDll,
    GetLogs,   // NEW: Get kernel debug logs
    ClearLogs, // NEW: Clear kernel log buffer
    GetStatus, // NEW: Get driver status info
    Max
};

static constexpr int DRIVER_REQUEST_MAGIC = 'Bcta';

//=============================================================================
// Base Request Header
//=============================================================================
typedef struct _DRIVER_REQUEST_HEADER
{
    int Magic = DRIVER_REQUEST_MAGIC;
    EDriverCommunicationRequest Request = EDriverCommunicationRequest::Invalid;
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;

    bool IsValid(void) const
    {
        return (this->Magic == DRIVER_REQUEST_MAGIC && (this->Request > EDriverCommunicationRequest::Invalid &&
                                                        this->Request < EDriverCommunicationRequest::Max));
    }

    void SetStatus(_In_ const NTSTATUS status)
    {
        this->Status = status;
    }

} DRIVER_REQUEST_HEADER, *PDRIVER_REQUEST_HEADER;

//=============================================================================
// Inject DLL Request
//=============================================================================
typedef struct _DRIVER_REQUEST_INJECT : DRIVER_REQUEST_HEADER
{
    PVOID ImageBase;
    ULONG ImageSize;

    _DRIVER_REQUEST_INJECT(_In_ PVOID imageBase, _In_ ULONG imageSize) : ImageBase(imageBase), ImageSize(imageSize)
    {
        this->Request = EDriverCommunicationRequest::InjectDll;
    }

} DRIVER_REQUEST_INJECT, *PDRIVER_REQUEST_INJECT;

//=============================================================================
// Disable Bypass Request
//=============================================================================
typedef struct _DRIVER_REQUEST_DISABLE_BYPASS : DRIVER_REQUEST_HEADER
{
    _DRIVER_REQUEST_DISABLE_BYPASS()
    {
        this->Request = EDriverCommunicationRequest::DisableBypass;
    }

} DRIVER_REQUEST_DISABLE_BYPASS, *PDRIVER_REQUEST_DISABLE_BYPASS;

//=============================================================================
// Enable Bypass Request
//=============================================================================
typedef struct _DRIVER_REQUEST_ENABLE_BYPASS : DRIVER_REQUEST_HEADER
{
    _DRIVER_REQUEST_ENABLE_BYPASS()
    {
        this->Request = EDriverCommunicationRequest::EnableBypass;
    }

} DRIVER_REQUEST_ENABLE_BYPASS, *PDRIVER_REQUEST_ENABLE_BYPASS;

//=============================================================================
// Get Logs Request - Retrieve kernel debug logs
//=============================================================================
typedef struct _DRIVER_REQUEST_GET_LOGS : DRIVER_REQUEST_HEADER
{
    ULONG MaxEntries;                          // Max entries to retrieve (input)
    ULONG EntriesReturned;                     // Actual entries returned (output)
    ULONG TotalEntriesAvailable;               // Total entries in kernel buffer (output)
    ULONG EntriesDropped;                      // Entries dropped due to buffer overflow (output)
    DRIVER_LOG_ENTRY Entries[MAX_LOG_ENTRIES]; // Log entries array (output)

    _DRIVER_REQUEST_GET_LOGS(_In_ ULONG maxEntries = MAX_LOG_ENTRIES)
        : MaxEntries(maxEntries), EntriesReturned(0), TotalEntriesAvailable(0), EntriesDropped(0)
    {
        this->Request = EDriverCommunicationRequest::GetLogs;
    }

} DRIVER_REQUEST_GET_LOGS, *PDRIVER_REQUEST_GET_LOGS;

//=============================================================================
// Clear Logs Request - Clear kernel log buffer
//=============================================================================
typedef struct _DRIVER_REQUEST_CLEAR_LOGS : DRIVER_REQUEST_HEADER
{
    ULONG EntriesCleared; // Number of entries that were cleared (output)

    _DRIVER_REQUEST_CLEAR_LOGS() : EntriesCleared(0)
    {
        this->Request = EDriverCommunicationRequest::ClearLogs;
    }

} DRIVER_REQUEST_CLEAR_LOGS, *PDRIVER_REQUEST_CLEAR_LOGS;

//=============================================================================
// Get Status Request - Get driver status information
//=============================================================================
typedef struct _DRIVER_REQUEST_GET_STATUS : DRIVER_REQUEST_HEADER
{
    BOOLEAN BypassEnabled;      // Is bypass currently enabled
    BOOLEAN HooksInstalled;     // Are syscall hooks installed
    ULONG TargetProcessId;      // Current target process ID
    ULONG64 InjectionCount;     // Number of successful injections
    ULONG64 HookedSyscallCount; // Number of syscalls intercepted
    ULONG LogBufferUsage;       // Current log buffer usage (entries)
    CHAR TargetProcessName[64]; // Current target process name

    _DRIVER_REQUEST_GET_STATUS()
        : BypassEnabled(FALSE), HooksInstalled(FALSE), TargetProcessId(0), InjectionCount(0), HookedSyscallCount(0),
          LogBufferUsage(0)
    {
        this->Request = EDriverCommunicationRequest::GetStatus;
        TargetProcessName[0] = '\0';
    }

} DRIVER_REQUEST_GET_STATUS, *PDRIVER_REQUEST_GET_STATUS;

} // namespace Comms