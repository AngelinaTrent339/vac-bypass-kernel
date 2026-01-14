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
#include "includes.hpp"

namespace Callbacks
{
void ProcessCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
                     _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateNotifyInfo);

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_ALT_SYSCALL)
void ThreadCallback(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
#endif

bool g_initialized = false;

void Cleanup()
{
#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_ALT_SYSCALL)
    PsRemoveCreateThreadNotifyRoutine(&ThreadCallback);
#endif
    PsSetCreateProcessNotifyRoutineEx(&ProcessCallback, TRUE);
}

NTSTATUS Initialize()
{
    PAGED_PASSIVE();

    if (g_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    NTSTATUS status;

    status = PsSetCreateProcessNotifyRoutineEx(&ProcessCallback, FALSE);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "PsSetCreateProcessNotifyRoutineEx returned %!STATUS!", status);
        goto Exit;
    }

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_ALT_SYSCALL)
    // Register thread creation callback to enable AltSyscall on new threads in game process
    status = PsSetCreateThreadNotifyRoutine(&ThreadCallback);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "PsSetCreateThreadNotifyRoutine returned %!STATUS!", status);
        goto Exit;
    }
#endif

    g_initialized = true;

Exit:
    if (!NT_SUCCESS(status))
    {
        Cleanup();
        status = STATUS_UNSUCCESSFUL;
    }
    return status;
}

void Unitialize()
{
    PAGED_PASSIVE();

    if (!g_initialized)
    {
        return;
    }

    Cleanup();
}

void ProcessCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
                     _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateNotifyInfo)
{
    UNREFERENCED_PARAMETER(Process);

    static bool gameFound = false;

    if (CreateNotifyInfo)
    {
        // On process creation.
        if (!CreateNotifyInfo->ImageFileName || !CreateNotifyInfo->ImageFileName->Buffer)
        {
            return;
        }

        NTSTATUS status;

        UNICODE_STRING robloxPlayer{};
        RtlInitUnicodeString(&robloxPlayer, L"RobloxPlayerBeta.exe");

        if (RtlSuffixUnicodeString(&robloxPlayer, CreateNotifyInfo->ImageFileName, TRUE) && !gameFound)
        {
            gameFound = true;

            WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Adding image %wZ (%d) to game list",
                      CreateNotifyInfo->ImageFileName, HandleToULong(ProcessId));

            status = Processes::AddProcessGame(ProcessId);
            if (!NT_SUCCESS(status))
            {
                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "AddProcessGame returned %!STATUS!", status);
            }

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_ALT_SYSCALL)
            // Enable Alt Syscall for Roblox process
            if (SyscallHook::g_AltSyscallRegistered)
            {
                status = SyscallHook::EnableAltSyscallForProcess(Process);
                if (!NT_SUCCESS(status))
                {
                    WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, 
                              "EnableAltSyscallForProcess returned %!STATUS!", status);
                }
                else
                {
                    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, 
                              "Alt Syscall enabled for Roblox process %d", HandleToULong(ProcessId));
                }
            }
#endif
        }
    }
    else
    {
        // On process termination.
        Bypass::EraseGameModules(ProcessId);
        Bypass::EraseProtectedModules(ProcessId);

        if (Processes::IsProcessGame(ProcessId))
        {
            gameFound = false;
        }

        if (Processes::IsProcessInList(ProcessId))
        {
            WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Removing %s (%d) from list",
                      (PCHAR)PsGetProcessImageFileName(Process), HandleToULong(ProcessId));

            if (!Processes::RemoveProcess(ProcessId))
            {
                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to remove process id %d from processes list!",
                          HandleToULong(ProcessId));
            }
        }
    }
}

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_ALT_SYSCALL)
void ThreadCallback(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ProcessId);
    
    // Only handle thread creation
    if (!Create)
    {
        return;
    }
    
    // Skip if Alt Syscall handler is not registered
    if (!SyscallHook::g_AltSyscallRegistered)
    {
        return;
    }
    
    // Get the thread object
    PETHREAD Thread = nullptr;
    NTSTATUS status = PsLookupThreadByThreadId(ThreadId, &Thread);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    
    // Enable Alt Syscall for ALL new threads (for system-wide code integrity spoofing)
    SyscallHook::EnableAltSyscallForThread(Thread);
    SyscallHook::ConfigureProcessForAltSyscall(Thread);
    
    ObDereferenceObject(Thread);
}
#endif

} // namespace Callbacks