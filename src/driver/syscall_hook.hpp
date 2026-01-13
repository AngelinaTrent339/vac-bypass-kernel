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

namespace SyscallHook
{
inline Threads::KERNEL_THREAD g_SyscallHookThread = {};

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
typedef VOID(__fastcall *SSDT_CALLBACK)(ULONG, PVOID *);

inline SSDT_CALLBACK g_SsdtCallback = NULL;
inline PVOID g_SyscallTableAddress = nullptr;

inline PVOID *g_GetCpuClock = nullptr;
inline PVOID *g_HvlpReferenceTscPage = nullptr;
inline PVOID *g_HvlGetQpcBias = nullptr;

inline PVOID g_HvlGetQpcBiasOriginal = nullptr;
inline PVOID g_GetCpuClockOriginal = nullptr;

ULONG64
SyscallHookHandler(VOID);

[[nodiscard]] NTSTATUS Initialize(_In_ SSDT_CALLBACK SsdtCallback = Hooks::SsdtCallback);
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_SSDT_HOOK)
[[nodiscard]] NTSTATUS Initialize();
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_ALT_SYSCALL)
// ============================================================================
// Alt Syscall Handler - Windows 11 PatchGuard-Safe Method
// ============================================================================
//
// Windows 11 uses a completely different mechanism than Windows 10:
// - PsRegisterAltSystemCallHandler is NOT used (writes to array that's never read)
// - Instead, we write to PspServiceDescriptorGroupTable directly
// - Set KTHREAD->Header.DebugActive |= 0x20 to enable per-thread
// - Set EPROCESS->SyscallProviderDispatchContext.Slot to select our table row
//
// Callback receives: (void* p_nt_function, ULONG ssn, void* args_base, void* p3_home)
//
// Limitations:
// - HVCI prevents writes to PspServiceDescriptorGroupTable
// - Windows 11 only (tested on 24H2)
// - Undocumented, may break in future versions
//

inline bool g_AltSyscallRegistered = false;

// Enables Alt Syscall for a specific thread (sets DebugActive bit 0x20)
NTSTATUS EnableAltSyscallForThread(_In_ PETHREAD Thread);

// Disables Alt Syscall for a specific thread
NTSTATUS DisableAltSyscallForThread(_In_ PETHREAD Thread);

// Enables Alt Syscall for all threads in a process
NTSTATUS EnableAltSyscallForProcess(_In_ PEPROCESS Process);

// Disables Alt Syscall for all threads in a process
NTSTATUS DisableAltSyscallForProcess(_In_ PEPROCESS Process);

[[nodiscard]] NTSTATUS Initialize();
#endif

void Unitialize();
void Cleanup();
}; // namespace SyscallHook