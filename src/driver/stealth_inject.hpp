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

//
// Stealth DLL Injection for Roblox/Hyperion
// 
// This module implements a guaranteed stealth injection method that bypasses:
// - Memory whitelisting (our memory doesn't exist to usermode)
// - Integrity checks (cannot hash what cannot be read)
// - Thread enumeration (our threads are invisible)
// - Context checks (hijacked thread context is spoofed)
//
// Technique: Thread Hijacking + Hidden Memory
// 1. Allocate memory and mark as hidden (invisible to all syscalls)
// 2. Manual map DLL into hidden memory
// 3. Find a suitable thread in the target process
// 4. Suspend thread, save context
// 5. Hijack RIP to execute our DllMain
// 6. Resume thread, wait for completion signal
// 7. Restore original context
//
// All memory operations are invisible because:
// - NtQueryVirtualMemory returns STATUS_INVALID_ADDRESS for hidden regions
// - NtReadVirtualMemory returns STATUS_PARTIAL_COPY for hidden regions
// - Thread enumeration filters out hidden/hijacked threads
// - NtGetContextThread returns saved context for hijacked threads
//

namespace StealthInject
{

// Injection result codes
enum class INJECT_STATUS : ULONG
{
    Success = 0,
    ProcessNotFound,
    NoSuitableThread,
    AllocationFailed,
    MappingFailed,
    ThreadHijackFailed,
    ExecutionFailed,
    ContextRestoreFailed,
    ModuleNotFound,
    InternalError
};

// Injection configuration
typedef struct _STEALTH_INJECT_CONFIG
{
    BOOLEAN UseThreadHijack;      // TRUE = hijack existing thread, FALSE = create hidden thread
    BOOLEAN WaitForCompletion;    // TRUE = wait for DllMain to complete
    ULONG TimeoutMs;              // Timeout in milliseconds (0 = infinite)
    PVOID NotificationAddress;    // Optional: address to signal when done

} STEALTH_INJECT_CONFIG, *PSTEALTH_INJECT_CONFIG;

// Initialize stealth injection subsystem
[[nodiscard]] NTSTATUS Initialize();

// Cleanup stealth injection subsystem
void Uninitialize();

// Main injection function - inject DLL into Roblox process
// This is the guaranteed injection method
[[nodiscard]] INJECT_STATUS InjectDll(
    _In_ PEPROCESS TargetProcess,
    _In_ PVOID DllBuffer,
    _In_ SIZE_T DllSize,
    _In_opt_ PSTEALTH_INJECT_CONFIG Config = nullptr
);

// Attach to process and inject
[[nodiscard]] INJECT_STATUS AttachAndInject(
    _In_ PEPROCESS TargetProcess,
    _In_ PVOID DllBuffer,
    _In_ SIZE_T DllSize,
    _In_opt_ PSTEALTH_INJECT_CONFIG Config = nullptr
);

// Find a suitable thread for hijacking
[[nodiscard]] NTSTATUS FindHijackableThread(
    _In_ PEPROCESS Process,
    _Out_ PETHREAD *Thread
);

// Perform thread hijack injection
[[nodiscard]] NTSTATUS HijackThreadAndExecute(
    _In_ PETHREAD Thread,
    _In_ PVOID ExecutionAddress,
    _In_opt_ PVOID Parameter,
    _In_ BOOLEAN WaitForCompletion,
    _In_ ULONG TimeoutMs
);

// Allocate hidden memory (invisible to usermode)
[[nodiscard]] NTSTATUS AllocateHiddenMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG Protect
);

} // namespace StealthInject
