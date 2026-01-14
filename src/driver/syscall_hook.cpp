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

namespace SyscallHook
{
bool g_initialized = false;

const bool IsInitialized()
{
    return g_initialized;
}

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
enum CKCL_TRACE_OPERATION
{
    CKCL_TRACE_START,
    CKCL_TRACE_SYSCALL,
    CKCL_TRACE_END
};

typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
    ULONG64 Unknown[3];
    UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, *PCKCL_TRACE_PROPERTIES;

PVOID GetSyscallEntry();

ULONG64
hkHvlGetQpcBias(VOID);

BOOLEAN
StartSyscallHook(VOID);

NTSTATUS
ModifyTraceSettings(_In_ const CKCL_TRACE_OPERATION &TraceOperation);

NTSTATUS InitializeInfinityHook()
{
    NTSTATUS Status;

    Status = ModifyTraceSettings(CKCL_TRACE_SYSCALL);
    if (!NT_SUCCESS(Status))
    {
        Status = ModifyTraceSettings(CKCL_TRACE_START);
        if (!NT_SUCCESS(Status))
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL,
                      "ModifyTraceSettings(CKCL_TRACE_START) "
                      "failed %!STATUS!",
                      Status);

            return Status;
        }

        Status = ModifyTraceSettings(CKCL_TRACE_SYSCALL);
        if (!NT_SUCCESS(Status))
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL,
                      "ModifyTraceSettings(CKCL_TRACE_SYSCALL) "
                      "failed %!STATUS!",
                      Status);

            return Status;
        }
    }

    ULONG64 CkclWmiLoggerContext;
    PVOID EtwpDebuggerData;
    PULONG64 EtwpDebuggerDataSilo;
    PVOID syscallEntry;

    EtwpDebuggerData = reinterpret_cast<VOID *>(Dynamic::g_DynamicContext.Kernel.Address.EtwpDebuggerData);

    DBG_PRINT("EtwpDebuggerData = 0x%p", EtwpDebuggerData);

    EtwpDebuggerDataSilo = *reinterpret_cast<PULONG64 *>(PTR_OFFSET_ADD(EtwpDebuggerData, 0x10));

    DBG_PRINT("EtwpDebuggerDataSilo = 0x%p", EtwpDebuggerDataSilo);

    if (!MmIsAddressValid(EtwpDebuggerDataSilo))
    {
        goto Exit;
    }

    CkclWmiLoggerContext = EtwpDebuggerDataSilo[2];

    DBG_PRINT("CkclWmiLoggerContext = 0x%016llX", CkclWmiLoggerContext);

    if (!CkclWmiLoggerContext)
    {
        goto Exit;
    }

    g_GetCpuClock = Dynamic::g_DynamicContext.Kernel.GetCpuClock(CkclWmiLoggerContext);

    DBG_PRINT("g_GetCpuClock = 0x%p", g_GetCpuClock);

    if (!MmIsAddressValid(g_GetCpuClock))
    {
        goto Exit;
    }

    syscallEntry = GetSyscallEntry();
    if (!syscallEntry)
    {
        goto Exit;
    }

    DBG_PRINT("syscallEntry = 0x%p", syscallEntry);

    g_SyscallTableAddress = PAGE_ALIGN(syscallEntry);

    DBG_PRINT("g_SyscallTableAddress = 0x%p", g_SyscallTableAddress);

    if (!g_SyscallTableAddress)
    {
        goto Exit;
    }

    if (StartSyscallHook())
    {
        return STATUS_SUCCESS;
    }

Exit:
    return STATUS_UNSUCCESSFUL;
}

void CleanupInfinityHook()
{
    if (g_SyscallHookThread.Status == Threads::KERNEL_THREAD_STATUS::Running)
    {
        Threads::StopThread(&g_SyscallHookThread, TRUE);
    }

    if (g_GetCpuClock)
    {
        InterlockedExchangePointer(g_GetCpuClock, g_GetCpuClockOriginal);
    }

    if (g_HvlGetQpcBias)
    {
        InterlockedExchangePointer(g_HvlGetQpcBias, g_HvlGetQpcBiasOriginal);
    }

    NTSTATUS Status = ModifyTraceSettings(CKCL_TRACE_END);
    if (NT_SUCCESS(Status))
    {
        ModifyTraceSettings(CKCL_TRACE_START);
    }
}

BOOLEAN WatchdogThread(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    // This will ensure infinityhook is still active all the time
    //
    if (NTOS_BUILD <= WINVER_WIN10_1909)
    {
        if (g_GetCpuClock && MmIsAddressValid(g_GetCpuClock))
        {
            PVOID oldValue =
                InterlockedCompareExchangePointer(g_GetCpuClock, &SyscallHookHandler, g_GetCpuClockOriginal);
            if (oldValue == g_GetCpuClockOriginal)
            {
                g_GetCpuClockOriginal = oldValue;
            }
        }
    }
    else
    {
        if (g_GetCpuClock && MmIsAddressValid(g_GetCpuClock))
        {
            PVOID oldValue = InterlockedCompareExchangePointer(g_GetCpuClock, ULongToPtr(2), g_GetCpuClockOriginal);
            if (oldValue == g_GetCpuClockOriginal)
            {
                g_GetCpuClockOriginal = oldValue;
            }
        }

        if (g_HvlGetQpcBias && MmIsAddressValid(g_HvlGetQpcBias))
        {
            PVOID oldValue =
                InterlockedCompareExchangePointer(g_HvlGetQpcBias, &hkHvlGetQpcBias, g_HvlGetQpcBiasOriginal);
            if (oldValue == g_HvlGetQpcBiasOriginal)
            {
                g_HvlGetQpcBiasOriginal = oldValue;
            }
        }
    }

    Misc::DelayThread(512);

    // Keep executing as long as thread is not signalized to stop.
    //
    return FALSE;
}

BOOLEAN
StartSyscallHook(VOID)
{
    PAGED_PASSIVE();
    NT_ASSERT(g_SsdtCallback);

    BOOLEAN bResult = FALSE;

    if (!g_GetCpuClock || !MmIsAddressValid(g_GetCpuClock))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Invalid g_GetCpuClock!");
        goto Exit;
    }

    if (NTOS_BUILD <= WINVER_WIN10_1909)
    {
        g_GetCpuClockOriginal = InterlockedExchangePointer(g_GetCpuClock, &SyscallHookHandler);

        DBG_PRINT("g_GetCpuClock = 0x%p", g_GetCpuClock);
        DBG_PRINT("g_GetCpuClockOriginal = 0x%p", g_GetCpuClockOriginal);
    }
    else
    {
        g_GetCpuClockOriginal = InterlockedExchangePointer(g_GetCpuClock, ULongToPtr(2));

        DBG_PRINT("g_GetCpuClock = 0x%p", g_GetCpuClock);
        DBG_PRINT("g_GetCpuClockOriginal = 0x%p", g_GetCpuClockOriginal);

        ULONG_PTR HvlpReferenceTscPage = Dynamic::g_DynamicContext.Kernel.Address.HvlpReferenceTscPage;

        g_HvlpReferenceTscPage = RipToAbsolute<PVOID *>(HvlpReferenceTscPage, 3, 7);
        DBG_PRINT("g_HvlpReferenceTscPage = 0x%p", g_HvlpReferenceTscPage);

        ULONG_PTR HvlGetQpcBias = Dynamic::g_DynamicContext.Kernel.Address.HvlGetQpcBias;

        g_HvlGetQpcBias = RipToAbsolute<PVOID *>(HvlGetQpcBias, 3, 7);
        DBG_PRINT("g_HvlGetQpcBias = 0x%p", g_HvlGetQpcBias);

        g_HvlGetQpcBiasOriginal = InterlockedExchangePointer(g_HvlGetQpcBias, &hkHvlGetQpcBias);
        DBG_PRINT("g_HvlGetQpcBiasOriginal = 0x%p", g_HvlGetQpcBiasOriginal);
    }

    if (!Threads::CreateThread(&WatchdogThread, nullptr, &g_SyscallHookThread))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to create syscall hook watchdog thread!");
        goto Exit;
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Syscall watchdog thread id %d",
              HandleToULong(g_SyscallHookThread.ClientId.UniqueThread));

    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Successfully initialized syscall hooks.");

    bResult = TRUE;

Exit:
    if (!bResult)
    {
        Cleanup();
    }

    return bResult;
}

NTSTATUS
ModifyTraceSettings(_In_ const CKCL_TRACE_OPERATION &TraceOperation)
{
    PAGED_PASSIVE();

    auto traceProperty =
        reinterpret_cast<CKCL_TRACE_PROPERTIES *>(Memory::AllocNonPaged(PAGE_SIZE, Memory::TAG_SYSCALL_HOOK));
    if (!traceProperty)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL,
                  "Could not allocate "
                  "memory for trace properties!");

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SCOPE_EXIT
    {
        Memory::FreePool(traceProperty);
    };

    traceProperty->Wnode.BufferSize = PAGE_SIZE;
    traceProperty->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    traceProperty->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
    traceProperty->Wnode.Guid = {0x54DEA73A, 0xED1F, 0x42A4, {0xAF, 0x71, 0x3E, 0x63, 0xD0, 0x56, 0xF1, 0x74}};
    traceProperty->Wnode.ClientContext = 1;
    traceProperty->BufferSize = sizeof(ULONG);
    traceProperty->MinimumBuffers = traceProperty->MaximumBuffers = 2;
    traceProperty->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

    NTSTATUS status = STATUS_ACCESS_DENIED;
    ULONG returnLength = 0UL;

    switch (TraceOperation)
    {
    case CKCL_TRACE_START: {
        status = ZwTraceControl(EtwpStartTrace, traceProperty, PAGE_SIZE, traceProperty, PAGE_SIZE, &returnLength);
        break;
    }
    case CKCL_TRACE_END: {
        status = ZwTraceControl(EtwpStopTrace, traceProperty, PAGE_SIZE, traceProperty, PAGE_SIZE, &returnLength);
        break;
    }
    case CKCL_TRACE_SYSCALL: {
        traceProperty->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
        status = ZwTraceControl(EtwpUpdateTrace, traceProperty, PAGE_SIZE, traceProperty, PAGE_SIZE, &returnLength);
        break;
    }
    }

    return status;
}

PVOID GetSyscallEntry()
{
    PAGED_PASSIVE();

    PIMAGE_NT_HEADERS64 nth = RtlImageNtHeader(NTOS_BASE);
    if (!nth)
    {
        return nullptr;
    }

    PVOID syscallEntry = reinterpret_cast<PVOID>(__readmsr(IA32_LSTAR_MSR));

    // If KVASCODE section does not exists it probably means the system does not support it.
    //
    PIMAGE_SECTION_HEADER section = Misc::PE::FindSection(nth, "KVASCODE");
    if (!section)
    {
        return syscallEntry;
    }

    const PVOID sectionBase = reinterpret_cast<PUCHAR>(NTOS_BASE) + section->VirtualAddress;
    const ULONG sectionSize = section->Misc.VirtualSize;

    // Is the value within this KVA shadow region? If not, we're done.
    //
    if (!(syscallEntry >= sectionBase && syscallEntry < reinterpret_cast<PUCHAR>(sectionBase) + sectionSize))
    {
        return syscallEntry;
    }

    // This is KiSystemCall64Shadow.
    //
    hde64s HDE;
    for (PUCHAR KiSystemServiceUser = reinterpret_cast<PUCHAR>(syscallEntry); /* */; KiSystemServiceUser += HDE.len)
    {
        // Disassemble every instruction till the first near jmp (E9).
        //
        if (!hde64_disasm(KiSystemServiceUser, &HDE))
        {
            break;
        }

        if (HDE.opcode != 0xE9)
        {
            continue;
        }

        // Ignore jmps within the KVA shadow region.
        //
        PVOID possibleSyscallEntry = KiSystemServiceUser + (int)HDE.len + (int)HDE.imm.imm32;
        if (possibleSyscallEntry >= sectionBase &&
            possibleSyscallEntry < reinterpret_cast<PUCHAR>(sectionBase) + sectionSize)
        {
            continue;
        }

        // Found KiSystemServiceUser.
        //
        syscallEntry = possibleSyscallEntry;
        break;
    }

    return syscallEntry;
}

ULONG64
SyscallHookHandler(VOID)
{
#define INFINITYHOOK_MAGIC_1 ((ULONG)0x501802)
#define INFINITYHOOK_MAGIC_2 ((USHORT)0xF33)

    if (ExGetPreviousMode() == KernelMode)
    {
        return __rdtsc();
    }

    const auto currentThread = __readgsqword(0x188);
    const ULONG systemCallIndex = *(ULONG *)(currentThread + 0x80); // KTHREAD->SystemCallNumber

    const auto stackMax = __readgsqword(KPCR_RSP_BASE);
    const PVOID *stackFrame = (PVOID *)_AddressOfReturnAddress();

    UINT offset = 0;

    // First walk backwards on the stack to find the 2 magic values.
    for (PVOID *stackCurrent = (PVOID *)stackMax; stackCurrent > stackFrame; --stackCurrent)
    {
        PULONG AsUlong = (PULONG)stackCurrent;
        if (*AsUlong != INFINITYHOOK_MAGIC_1)
        {
            continue;
        }

        // If the first magic is set, check for the second magic.
        --stackCurrent;

        PUSHORT AsShort = (PUSHORT)stackCurrent;
        if (*AsShort != INFINITYHOOK_MAGIC_2)
        {
            continue;
        }

        // Now we reverse the direction of the stack walk.
        for (; (ULONG_PTR)stackCurrent < stackMax; ++stackCurrent)
        {
            PULONGLONG AsUlonglong = (PULONGLONG)stackCurrent;

            if (!(PAGE_ALIGN(*AsUlonglong) >= g_SyscallTableAddress &&
                  PAGE_ALIGN(*AsUlonglong) < (PVOID)((uintptr_t)g_SyscallTableAddress + (PAGE_SIZE * 2))))
            {
                continue;
            }

            offset = (UINT)((ULONG_PTR)stackCurrent - (ULONG_PTR)stackFrame);
            break;
        }

        break;
    }

    if (offset)
    {
        PVOID *stackCurrent = (PVOID *)((ULONG_PTR)stackFrame + offset);

        if (*(ULONG_PTR *)stackCurrent >= (ULONG_PTR)g_SyscallTableAddress &&
            *(ULONG_PTR *)stackCurrent < ((ULONG_PTR)g_SyscallTableAddress + (PAGE_SIZE * 2)))
        {
            PVOID *systemCallFunction = &stackCurrent[9];

            if (g_SsdtCallback)
            {
                g_SsdtCallback(systemCallIndex, systemCallFunction);
            }
        }
    }

    return __rdtsc();
}

ULONG64
hkHvlGetQpcBias(VOID)
{
    SyscallHookHandler();

    return *((ULONG64 *)(*((ULONG64 *)g_HvlpReferenceTscPage)) + 3);
}
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_SSDT_HOOK)
BOOLEAN FindCodeCaveSection(_In_ ULONG_PTR SsdtBase, _In_ ULONG_PTR RoutineAddress, _Out_ PULONG_PTR SectionBase,
                            _Out_ PULONG SectionSize)
{
    PAGED_PASSIVE();

    PUCHAR sectionBase = nullptr;
    ULONG sectionSize = 0;

    *SectionBase = NULL;
    *SectionSize = NULL;

    if (!Misc::PE::GetSectionFromVirtualAddress(NTOS_BASE, reinterpret_cast<PUCHAR>(RoutineAddress), &sectionSize,
                                                &sectionBase))
    {

        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to find section from virtual address 0x%016llX", RoutineAddress);

        return FALSE;
    }

    ULONG_PTR baseFound = reinterpret_cast<ULONG_PTR>(sectionBase);
    ULONG_PTR Lowest = SsdtBase;

    if (baseFound < Lowest)
    {
        sectionSize -= static_cast<ULONG>(Lowest - baseFound);
        baseFound = Lowest;
    }

    *SectionBase = baseFound;
    *SectionSize = sectionSize;

    return TRUE;
}

void CleanupSsdtHook()
{
    auto serviceTable =
        reinterpret_cast<PSERVICE_DESCRIPTOR_TABLE>(Dynamic::g_DynamicContext.Kernel.Address.KeServiceDescriptorTable);

    // First unhook the SSDT entries
    //
    for (Hooks::SYSCALL_HOOK_ENTRY &entry : Hooks::g_SyscallHookList)
    {
        if (entry.OldSsdt && entry.NewSsdt)
        {
            Misc::Memory::WriteReadOnlyMemory(&serviceTable->NtosTable.ServiceTableBase[entry.ServiceIndex],
                                              &entry.OldSsdt, sizeof(entry.OldSsdt));
        }
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "SSDT Unhook -- Waiting for pending hooks...");

    // Wait for all pending hooks to complete
    //
    while (InterlockedCompareExchange(&Hooks::g_hooksRefCount, 0, 0) != 0)
    {
        YieldProcessor();
    }

    // Finally restore the code cave bytes
    //
    for (Hooks::SYSCALL_HOOK_ENTRY &entry : Hooks::g_SyscallHookList)
    {
        if (entry.OldSsdt && entry.NewSsdt)
        {
            Misc::Memory::WriteReadOnlyMemory(entry.NewRoutineAddress, entry.OriginalBytes,
                                              sizeof(entry.OriginalBytes));

            WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "SSDT Unhook -- ServiceIndex: %d", entry.ServiceIndex);

            entry.OldSsdt = NULL;
            entry.NewSsdt = NULL;
        }
    }
}

NTSTATUS InitializeSsdtHook()
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    auto serviceTable =
        reinterpret_cast<PSERVICE_DESCRIPTOR_TABLE>(Dynamic::g_DynamicContext.Kernel.Address.KeServiceDescriptorTable);
    const PULONG KiServiceTable = serviceTable->NtosTable.ServiceTableBase;

    for (Hooks::SYSCALL_HOOK_ENTRY &entry : Hooks::g_SyscallHookList)
    {
        // mov rax, 0
        // jmp rax
        static UCHAR TrampolineShellCode[12] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};

        auto SsdtBase = reinterpret_cast<ULONG_PTR>(KiServiceTable);

        const ULONG ServiceIndex = entry.ServiceIndex;
        if (ServiceIndex == ULONG_MAX)
        {
            continue;
        }

        LONG OldSsdt = KiServiceTable[ServiceIndex];
        LONG NewSsdt = 0;

        // Try to find possible code cave
        //
        ULONG_PTR CodeStart = 0;
        ULONG CodeSize = 0;

        if (!FindCodeCaveSection(SsdtBase, reinterpret_cast<ULONG_PTR>(entry.OriginalRoutineAddress), &CodeStart,
                                 &CodeSize))
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to find code cave section!");

            goto Exit;
        }

        ULONG_PTR CaveAddress = Misc::Memory::FindCodeCaveAddress(CodeStart, CodeSize, ARRAYSIZE(TrampolineShellCode));
        if (!CaveAddress)
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to find code cave address!");

            goto Exit;
        }

        // Write shellcode to code cave address
        //
        RtlCopyMemory(entry.OriginalBytes, reinterpret_cast<PVOID>(CaveAddress), ARRAYSIZE(entry.OriginalBytes));

        *(PVOID *)(&TrampolineShellCode[2]) = entry.NewRoutineAddress;

        Status = Misc::Memory::WriteReadOnlyMemory(reinterpret_cast<PVOID>(CaveAddress), TrampolineShellCode,
                                                   ARRAYSIZE(TrampolineShellCode));

        if (!NT_SUCCESS(Status))
        {

            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to write code cave, WriteReadOnlyMemory returned %!STATUS!",
                      Status);

            goto Exit;
        }

        // Update SSDT entry
        //
        NewSsdt = static_cast<LONG>(CaveAddress - SsdtBase);
        NewSsdt = (NewSsdt << 4) | OldSsdt & 0xF;

        Status = Misc::Memory::WriteReadOnlyMemory(&serviceTable->NtosTable.ServiceTableBase[ServiceIndex], &NewSsdt,
                                                   sizeof(NewSsdt));
        if (!NT_SUCCESS(Status))
        {

            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to SSDT entry, WriteReadOnlyMemory returned %!STATUS!",
                      Status);

            goto Exit;
        }

        entry.NewRoutineAddress = reinterpret_cast<PVOID>(CaveAddress);
        entry.NewSsdt = NewSsdt;
        entry.OldSsdt = OldSsdt;

        DBG_PRINT("SSDT Hook -- ServiceIndex: %d OriginalRoutineAddress: 0x%p "
                  "NewRoutineAddress: 0x%p OldSsdt: 0x%08X NewSsdt: 0x%08X",
                  entry.ServiceIndex, entry.OriginalRoutineAddress, entry.NewRoutineAddress, entry.OldSsdt,
                  entry.NewSsdt);
    }

    Status = STATUS_SUCCESS;

Exit:
    if (!NT_SUCCESS(Status))
    {
        CleanupSsdtHook();
    }

    return Status;
}
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_ALT_SYSCALL)
//
// Alt Syscall Handler Implementation for Windows 11
// 
// Windows 11 completely reworked the Alt Syscall mechanism from Windows 10.
// PsRegisterAltSystemCallHandler is NO LONGER used (it writes to PsAltSystemCallHandlers
// which is never read in Win11).
//
// Instead, Windows 11 uses:
// - PspServiceDescriptorGroupTable: A table with up to 32 slots (0x20 rows)
// - Each row contains: driver_base, ssn_dispatch_table, reserved
// - EPROCESS->SyscallProviderDispatchContext.Slot: Index into the table (must be < 20)
// - KTHREAD->Header.DebugActive: Set bit 0x20 to enable alt syscalls
//
// The callback signature for Windows 11 is:
//   int callback(void* p_nt_function, ULONG ssn, void* args_base, void* p3_home)
//
// Pros:
// - PatchGuard safe (not monitored)
// - HyperGuard safe (unless HVCI is enabled - which prevents writes to PspServiceDescriptorGroupTable)
// - Can intercept AND modify syscalls (return 0 to skip, modify KTRAP_FRAME directly)
// - Full access to arguments
//
// Cons:
// - HVCI blocks writes to PspServiceDescriptorGroupTable
// - Undocumented and may break in future Windows versions
// - Requires pattern scanning to find PspServiceDescriptorGroupTable
// - Windows 11 only (24H2 tested)
//

// ============================================================================
// Structures for Windows 11 Alt Syscalls
// ============================================================================

// The dispatch table entry - contains RVA offsets to callback functions
// Count is the maximum SSN this table handles
// Descriptors contain: (RVA << 4) | flags
//   - flags & 0x10: Use generic dispatch path
//   - flags & 0x0F: Number of QWORDs to copy from stack
#define ALT_SYSCALL_SSN_COUNT 0x200  // Maximum SSN count we support

#pragma pack(push, 1)
typedef struct _ALT_SYSCALL_DISPATCH_TABLE
{
    ULONG Count;                                // Number of SSNs we provide for (capacity) - MUST be ULONG
    ULONG Descriptors[ALT_SYSCALL_SSN_COUNT];   // Array of (RVA << 4) | flags
} ALT_SYSCALL_DISPATCH_TABLE, *PALT_SYSCALL_DISPATCH_TABLE;

// Each row in PspServiceDescriptorGroupTable
typedef struct _PSP_SERVICE_DESCRIPTOR_ROW
{
    PVOID DriverBase;                           // Base address of the driver
    PALT_SYSCALL_DISPATCH_TABLE DispatchTable;  // Pointer to our dispatch table
    PVOID Reserved;                             // Unused
} PSP_SERVICE_DESCRIPTOR_ROW, *PPSP_SERVICE_DESCRIPTOR_ROW;

// The main table - up to 32 slots
typedef struct _PSP_SERVICE_DESCRIPTOR_GROUP_TABLE
{
    PSP_SERVICE_DESCRIPTOR_ROW Rows[0x20];
} PSP_SERVICE_DESCRIPTOR_GROUP_TABLE, *PPSP_SERVICE_DESCRIPTOR_GROUP_TABLE;

// EPROCESS->SyscallProviderDispatchContext structure
typedef struct _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT
{
    ULONG Level;    // Unknown purpose
    ULONG Slot;     // Index into PspServiceDescriptorGroupTable (must be < 20)
} PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT, *PPSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT;
#pragma pack(pop)

// ============================================================================
// Windows 11 Version-Specific Offsets
// ============================================================================

// Offsets for Windows 11 24H2 (26100)
// These WILL change between Windows versions!
constexpr ULONG OFFSET_EPROCESS_SYSCALL_PROVIDER_DISPATCH_CTX = 0x7D0;
constexpr ULONG OFFSET_KTHREAD_DEBUG_ACTIVE = 0x03;  // DISPATCHER_HEADER.DebugActive
constexpr ULONG OFFSET_EPROCESS_ACTIVE_PROCESS_LINKS = 0x1D8;
constexpr ULONG OFFSET_EPROCESS_THREAD_LIST_HEAD = 0x370;
constexpr ULONG OFFSET_ETHREAD_THREAD_LIST_ENTRY = 0x578;

// Alt syscall enable bit in DebugActive
constexpr UCHAR ALT_SYSCALL_DEBUG_ACTIVE_BIT = 0x20;

// Slot ID we use (avoid 0 as it may be reserved, use 1-19)
constexpr ULONG ALT_SYSCALL_SLOT_ID = 1;

// Flags for the dispatch table entries
constexpr ULONG GENERIC_PATH_FLAGS = 0x10;  // Use PspSyscallProviderServiceDispatchGeneric
constexpr ULONG NUM_STACK_ARGS_TO_COPY = 0x0;  // We get stack args ourselves via p3_home

// ============================================================================
// Global Variables
// ============================================================================

inline PPSP_SERVICE_DESCRIPTOR_GROUP_TABLE g_PspServiceDescriptorGroupTable = nullptr;
inline PALT_SYSCALL_DISPATCH_TABLE g_AltSyscallDispatchTable = nullptr;
inline PVOID g_DriverBase = nullptr;

// ============================================================================
// Alt Syscall Callback
// ============================================================================

/// Windows 11 Alt Syscall callback routine
/// 
/// @param pNtFunction   Function pointer to the real Nt* dispatch function
/// @param Ssn           System Service Number of the syscall
/// @param ArgsBase      Base address of the first 4 arguments (rcx, rdx, r8, r9 - each 8 bytes)
/// @param P3Home        Address of P3Home field in KTRAP_FRAME (KTRAP_FRAME is at P3Home - 0x10)
/// 
/// @return 1 to continue normal syscall dispatch, 0 to skip syscall (return our own result)
///
ULONG64 __fastcall AltSyscallHandler(
    _In_ PVOID pNtFunction,
    _In_ ULONG Ssn,
    _In_ PVOID ArgsBase,
    _In_ PVOID P3Home)
{
    UNREFERENCED_PARAMETER(pNtFunction);
    
    if (!ArgsBase || !P3Home)
    {
        return 1;  // Continue normal dispatch
    }
    
    // Increment reference count
    InterlockedIncrement(&Hooks::g_hooksRefCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&Hooks::g_hooksRefCount);
    };
    
    // Calculate KTRAP_FRAME address from P3Home
    // P3Home is at offset 0x10 in KTRAP_FRAME
    PKTRAP_FRAME TrapFrame = reinterpret_cast<PKTRAP_FRAME>(
        reinterpret_cast<PUCHAR>(P3Home) - 0x10);
    
    // Get stack pointer for additional arguments (5th arg onwards)
    PVOID Rsp = reinterpret_cast<PVOID>(TrapFrame->Rsp);
    constexpr ULONG ARG5_STACK_OFFSET = 0x28;  // 5th arg is at RSP + 0x28
    
    // Extract first 4 arguments from ArgsBase
    PULONG_PTR Args = reinterpret_cast<PULONG_PTR>(ArgsBase);
    ULONG_PTR Arg1 = Args[0];  // RCX
    ULONG_PTR Arg2 = Args[1];  // RDX
    ULONG_PTR Arg3 = Args[2];  // R8
    ULONG_PTR Arg4 = Args[3];  // R9
    
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);
    UNREFERENCED_PARAMETER(Arg3);
    UNREFERENCED_PARAMETER(Arg4);
    UNREFERENCED_PARAMETER(Rsp);
    UNREFERENCED_PARAMETER(ARG5_STACK_OFFSET);
    
    // Check if this syscall is one we're interested in
    for (Hooks::SYSCALL_HOOK_ENTRY& Entry : Hooks::g_SyscallHookList)
    {
        if (Entry.ServiceIndex == Ssn && Entry.ServiceIndex != ULONG_MAX)
        {
            DBG_PRINT("[AltSyscall] Intercepted SSN 0x%X", Ssn);
            
            // TODO: Implement actual hook logic here
            // You can:
            // 1. Inspect arguments via ArgsBase
            // 2. Modify KTRAP_FRAME directly to change arguments
            // 3. Return 0 to skip the syscall entirely
            // 4. Modify TrapFrame->P3Home to change the return value (when returning 0)
            
            break;
        }
    }
    
    // Return 1 to continue normal syscall execution
    return 1;
}

// ============================================================================
// Pattern Scanning for PspServiceDescriptorGroupTable
// ============================================================================

/// Find PspServiceDescriptorGroupTable by pattern scanning
/// Based on Hells-Hollow approach: find PsSyscallProviderDispatch function first
PVOID FindPspServiceDescriptorGroupTable()
{
    DBG_PRINT("[AltSyscall] Searching for PsSyscallProviderDispatch function...");
    
    // Pattern for PsSyscallProviderDispatch function prologue (from Hells-Hollow)
    // This is the function start, not a reference to the table
    const UCHAR PsSyscallProviderDispatchPattern[] = {
        0x48, 0x89, 0x5c, 0x24, 0x08,  // mov qword ptr [rsp+8], rbx
        0x55,                           // push rbp
        0x56,                           // push rsi
        0x57,                           // push rdi
        0x41, 0x56,                     // push r14
        0x41, 0x57,                     // push r15
        0x48, 0x83, 0xec, 0x30,         // sub rsp, 30h
        0x48, 0x83, 0x64, 0x24, 0x70, 0x00,  // and qword ptr [rsp+70h], 0
        0x48, 0x8b, 0xf1,               // mov rsi, rcx
        0x65, 0x48, 0x8b, 0x2c, 0x25, 0x88, 0x01, 0x00, 0x00,  // mov rbp, gs:[188h]
        0xf6, 0x45, 0x03, 0x04          // test byte ptr [rbp+3], 4
    };
    
    // Search in ntoskrnl
    PIMAGE_NT_HEADERS64 nth = RtlImageNtHeader(NTOS_BASE);
    if (!nth)
    {
        DBG_PRINT("[AltSyscall] Failed to get NT headers");
        return nullptr;
    }
    
    PUCHAR BaseAddress = reinterpret_cast<PUCHAR>(NTOS_BASE);
    ULONG ImageSize = nth->OptionalHeader.SizeOfImage;
    
    DBG_PRINT("[AltSyscall] Scanning ntoskrnl at 0x%p, size 0x%X", BaseAddress, ImageSize);
    
    PUCHAR FunctionAddress = nullptr;
    for (ULONG i = 0; i < ImageSize - sizeof(PsSyscallProviderDispatchPattern); i++)
    {
        if (RtlCompareMemory(BaseAddress + i, PsSyscallProviderDispatchPattern, 
                             sizeof(PsSyscallProviderDispatchPattern)) == sizeof(PsSyscallProviderDispatchPattern))
        {
            FunctionAddress = BaseAddress + i;
            break;
        }
    }
    
    if (!FunctionAddress)
    {
        DBG_PRINT("[AltSyscall] Could not find PsSyscallProviderDispatch pattern!");
        return nullptr;
    }
    
    DBG_PRINT("[AltSyscall] Found PsSyscallProviderDispatch at 0x%p", FunctionAddress);
    
    // The instruction at offset 0x77 from function start references PspServiceDescriptorGroupTable
    // It's a "mov rax, [rip+disp32]" instruction (48 8B 05 xx xx xx xx)
    PUCHAR InstructionAddress = FunctionAddress + 0x77;
    
    DBG_PRINT("[AltSyscall] Instruction address: 0x%p", InstructionAddress);
    DBG_PRINT("[AltSyscall] Bytes at instruction: %02X %02X %02X %02X %02X %02X %02X",
              InstructionAddress[0], InstructionAddress[1], InstructionAddress[2],
              InstructionAddress[3], InstructionAddress[4], InstructionAddress[5], InstructionAddress[6]);
    
    // The instruction is "lea rcx, [rip+disp32]" which is 48 8D 0D (NOT 48 8B 05)
    // From disassembly: 488d0dd2167900  lea rcx,[nt!PspServiceDescriptorGroupTable]
    if (InstructionAddress[0] != 0x48 || InstructionAddress[1] != 0x8D || InstructionAddress[2] != 0x0D)
    {
        DBG_PRINT("[AltSyscall] WARNING: Expected 48 8D 0D (lea rcx) instruction at offset 0x77!");
        // Try to find it nearby - look for LEA instruction with RIP-relative addressing
        for (int offset = 0x70; offset < 0x90; offset++)
        {
            PUCHAR probe = FunctionAddress + offset;
            // 48 8D 0D = lea rcx, [rip+disp32]
            if (probe[0] == 0x48 && probe[1] == 0x8D && probe[2] == 0x0D)
            {
                DBG_PRINT("[AltSyscall] Found 48 8D 0D (lea rcx) at offset 0x%X", offset);
                InstructionAddress = probe;
                break;
            }
        }
    }
    
    // Read the 32-bit displacement (little-endian, at offset 3)
    INT32 disp32 = *reinterpret_cast<INT32*>(InstructionAddress + 3);
    // RIP-relative addressing: address = next_instruction + displacement
    PVOID resolved = reinterpret_cast<PVOID>(InstructionAddress + 7 + disp32);
    
    DBG_PRINT("[AltSyscall] disp32 = 0x%08X, resolved = 0x%p", disp32, resolved);
    
    // Validate the address
    if (!MmIsAddressValid(resolved))
    {
        DBG_PRINT("[AltSyscall] Resolved address is NOT VALID!");
        return nullptr;
    }
    
    // Dump first 48 bytes (2 rows) to verify structure
    PUCHAR ptr = reinterpret_cast<PUCHAR>(resolved);
    DBG_PRINT("[AltSyscall] First 48 bytes at table:");
    DBG_PRINT("[AltSyscall] Row0: %016llX %016llX %016llX",
              *reinterpret_cast<PULONG64>(ptr),
              *reinterpret_cast<PULONG64>(ptr + 8),
              *reinterpret_cast<PULONG64>(ptr + 16));
    DBG_PRINT("[AltSyscall] Row1: %016llX %016llX %016llX",
              *reinterpret_cast<PULONG64>(ptr + 24),
              *reinterpret_cast<PULONG64>(ptr + 32),
              *reinterpret_cast<PULONG64>(ptr + 40));
    
    return resolved;
}

// ============================================================================
// Thread/Process Configuration
// ============================================================================

NTSTATUS EnableAltSyscallForThread(_In_ PETHREAD Thread)
{
    if (!Thread)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Check if this is a Pico process thread (bit 0x04 in DebugActive)
    // We don't want to mess with WSL/Pico threads
    PUCHAR ThreadBase = reinterpret_cast<PUCHAR>(Thread);
    PUCHAR DebugActiveByte = ThreadBase + OFFSET_KTHREAD_DEBUG_ACTIVE;
    
    if ((*DebugActiveByte & 0x04) != 0)
    {
        // This is a Pico process thread, skip it
        return STATUS_SUCCESS;
    }
    
    // Set the AltSyscall bit (0x20) in DebugActive
    InterlockedOr8(reinterpret_cast<volatile CHAR*>(DebugActiveByte), ALT_SYSCALL_DEBUG_ACTIVE_BIT);
    
    DBG_PRINT("[AltSyscall] Enabled for thread 0x%p (DebugActive @ 0x%p = 0x%02X)", 
              Thread, DebugActiveByte, *DebugActiveByte);
    
    return STATUS_SUCCESS;
}

NTSTATUS DisableAltSyscallForThread(_In_ PETHREAD Thread)
{
    if (!Thread)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    PUCHAR ThreadBase = reinterpret_cast<PUCHAR>(Thread);
    PUCHAR DebugActiveByte = ThreadBase + OFFSET_KTHREAD_DEBUG_ACTIVE;
    
    // Clear the AltSyscall bit
    InterlockedAnd8(reinterpret_cast<volatile CHAR*>(DebugActiveByte), ~ALT_SYSCALL_DEBUG_ACTIVE_BIT);
    
    DBG_PRINT("[AltSyscall] Disabled for thread 0x%p", Thread);
    
    return STATUS_SUCCESS;
}

/// Configure EPROCESS for alt syscalls by setting the Slot field
void ConfigureProcessForAltSyscall(_In_ PETHREAD Thread)
{
    PEPROCESS Process = IoThreadToProcess(Thread);
    if (!Process)
    {
        return;
    }
    
    PUCHAR ProcessBase = reinterpret_cast<PUCHAR>(Process);
    PPSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT DispatchCtx = reinterpret_cast<PPSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT>(
        ProcessBase + OFFSET_EPROCESS_SYSCALL_PROVIDER_DISPATCH_CTX);
    
    // Set the slot ID
    DispatchCtx->Slot = ALT_SYSCALL_SLOT_ID;
    
    DBG_PRINT("[AltSyscall] Set process 0x%p slot to %u", Process, ALT_SYSCALL_SLOT_ID);
}

NTSTATUS EnableAltSyscallForProcess(_In_ PEPROCESS Process)
{
    if (!Process)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Enumerate all threads in the process using the thread list
    PUCHAR ProcessBase = reinterpret_cast<PUCHAR>(Process);
    PLIST_ENTRY ThreadListHead = reinterpret_cast<PLIST_ENTRY>(
        ProcessBase + OFFSET_EPROCESS_THREAD_LIST_HEAD);
    
    if (IsListEmpty(ThreadListHead))
    {
        return STATUS_SUCCESS;
    }
    
    PLIST_ENTRY Entry = ThreadListHead->Flink;
    while (Entry != ThreadListHead)
    {
        PETHREAD Thread = reinterpret_cast<PETHREAD>(
            reinterpret_cast<PUCHAR>(Entry) - OFFSET_ETHREAD_THREAD_LIST_ENTRY);
        
        EnableAltSyscallForThread(Thread);
        ConfigureProcessForAltSyscall(Thread);
        
        Entry = Entry->Flink;
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS DisableAltSyscallForProcess(_In_ PEPROCESS Process)
{
    if (!Process)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    PUCHAR ProcessBase = reinterpret_cast<PUCHAR>(Process);
    PLIST_ENTRY ThreadListHead = reinterpret_cast<PLIST_ENTRY>(
        ProcessBase + OFFSET_EPROCESS_THREAD_LIST_HEAD);
    
    if (IsListEmpty(ThreadListHead))
    {
        return STATUS_SUCCESS;
    }
    
    PLIST_ENTRY Entry = ThreadListHead->Flink;
    while (Entry != ThreadListHead)
    {
        PETHREAD Thread = reinterpret_cast<PETHREAD>(
            reinterpret_cast<PUCHAR>(Entry) - OFFSET_ETHREAD_THREAD_LIST_ENTRY);
        
        DisableAltSyscallForThread(Thread);
        
        Entry = Entry->Flink;
    }
    
    return STATUS_SUCCESS;
}

// ============================================================================
// Walk all processes and enable Alt Syscalls
// ============================================================================

void WalkActiveProcessesAndSetBits(bool Enable)
{
    PEPROCESS CurrentProcess = IoGetCurrentProcess();
    if (!CurrentProcess)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "IoGetCurrentProcess returned NULL");
        return;
    }
    
    PUCHAR ProcessBase = reinterpret_cast<PUCHAR>(CurrentProcess);
    PLIST_ENTRY ListHead = reinterpret_cast<PLIST_ENTRY>(
        ProcessBase + OFFSET_EPROCESS_ACTIVE_PROCESS_LINKS);
    PLIST_ENTRY Entry = ListHead->Flink;
    
    while (Entry != ListHead)
    {
        PEPROCESS Process = reinterpret_cast<PEPROCESS>(
            reinterpret_cast<PUCHAR>(Entry) - OFFSET_EPROCESS_ACTIVE_PROCESS_LINKS);
        
        // Skip PID 0 (Idle process)
        HANDLE Pid = PsGetProcessId(Process);
        if (Pid == 0)
        {
            Entry = Entry->Flink;
            continue;
        }
        
        if (Enable)
        {
            EnableAltSyscallForProcess(Process);
        }
        else
        {
            DisableAltSyscallForProcess(Process);
        }
        
        Entry = Entry->Flink;
    }
}

// ============================================================================
// Initialization and Cleanup
// ============================================================================

void CleanupAltSyscallHook()
{
    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "AltSyscall Cleanup -- Waiting for pending hooks...");
    
    // Wait for all pending hooks to complete
    while (InterlockedCompareExchange(&Hooks::g_hooksRefCount, 0, 0) != 0)
    {
        YieldProcessor();
    }
    
    // Disable AltSyscall bits on all processes
    WalkActiveProcessesAndSetBits(false);
    
    // Clear our row in PspServiceDescriptorGroupTable
    if (g_PspServiceDescriptorGroupTable)
    {
        RtlZeroMemory(&g_PspServiceDescriptorGroupTable->Rows[ALT_SYSCALL_SLOT_ID], 
                      sizeof(PSP_SERVICE_DESCRIPTOR_ROW));
    }
    
    // Free our dispatch table
    if (g_AltSyscallDispatchTable)
    {
        Memory::FreePool(g_AltSyscallDispatchTable);
        g_AltSyscallDispatchTable = nullptr;
    }
    
    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "AltSyscall Cleanup -- Complete");
}

NTSTATUS InitializeAltSyscallHook()
{
    PAGED_PASSIVE();
    
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    
    // Check Windows version - this only works on Windows 11
    if (NTOS_BUILD < WINVER_WIN11_21H2)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, 
                  "Alt Syscall (Win11 method) requires Windows 11. Build %u detected.", NTOS_BUILD);
        return STATUS_NOT_SUPPORTED;
    }
    
    DBG_PRINT("[AltSyscall] Initializing for Windows 11 build %u", NTOS_BUILD);
    
    // Get our driver's base address
    g_DriverBase = Misc::Module::GetDriverBase();
    if (!g_DriverBase)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to get driver base address");
        return STATUS_UNSUCCESSFUL;
    }
    
    DBG_PRINT("[AltSyscall] Driver base = 0x%p", g_DriverBase);
    
    // Find PspServiceDescriptorGroupTable
    g_PspServiceDescriptorGroupTable = reinterpret_cast<PPSP_SERVICE_DESCRIPTOR_GROUP_TABLE>(
        FindPspServiceDescriptorGroupTable());
    
    if (!g_PspServiceDescriptorGroupTable)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, 
                  "Failed to find PspServiceDescriptorGroupTable! Pattern may need updating for this build.");
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    DBG_PRINT("[AltSyscall] PspServiceDescriptorGroupTable = 0x%p", g_PspServiceDescriptorGroupTable);
    
    // Validate the address before we use it
    if (!MmIsAddressValid(g_PspServiceDescriptorGroupTable))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, 
                  "PspServiceDescriptorGroupTable address 0x%p is INVALID!", g_PspServiceDescriptorGroupTable);
        return STATUS_INVALID_ADDRESS;
    }
    
    DBG_PRINT("[AltSyscall] Address validated, allocating dispatch table...");
    
    // Allocate our dispatch table
    g_AltSyscallDispatchTable = reinterpret_cast<PALT_SYSCALL_DISPATCH_TABLE>(
        Memory::AllocNonPaged(sizeof(ALT_SYSCALL_DISPATCH_TABLE), Memory::TAG_SYSCALL_HOOK));
    
    if (!g_AltSyscallDispatchTable)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate dispatch table");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(g_AltSyscallDispatchTable, sizeof(ALT_SYSCALL_DISPATCH_TABLE));
    
    // Set the count (capacity)
    g_AltSyscallDispatchTable->Count = ALT_SYSCALL_SSN_COUNT;
    
    // Calculate the RVA of our callback from driver base
    ULONG_PTR CallbackAddress = reinterpret_cast<ULONG_PTR>(&AltSyscallHandler);
    ULONG_PTR RvaOffset = CallbackAddress - reinterpret_cast<ULONG_PTR>(g_DriverBase);
    
    // Safety check - offset must fit in a ULONG
    if (RvaOffset > MAXULONG)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, 
                  "Callback RVA offset too large: 0x%llX", RvaOffset);
        Memory::FreePool(g_AltSyscallDispatchTable);
        g_AltSyscallDispatchTable = nullptr;
        return STATUS_INTEGER_OVERFLOW;
    }
    
    DBG_PRINT("[AltSyscall] Callback = 0x%p, RVA = 0x%08X", 
              reinterpret_cast<PVOID>(CallbackAddress), static_cast<ULONG>(RvaOffset));
    
    // Fill the descriptor table
    // Each entry: (RVA << 4) | flags
    // flags = 0x10 for generic path + number of stack QWORDs to copy
    ULONG DescriptorValue = (static_cast<ULONG>(RvaOffset) << 4) | (GENERIC_PATH_FLAGS | (NUM_STACK_ARGS_TO_COPY & 0x0F));
    
    DBG_PRINT("[AltSyscall] Filling descriptor table with value 0x%08X", DescriptorValue);
    
    for (ULONG i = 0; i < ALT_SYSCALL_SSN_COUNT; i++)
    {
        g_AltSyscallDispatchTable->Descriptors[i] = DescriptorValue;
    }
    
    DBG_PRINT("[AltSyscall] Descriptor table filled, writing to PspServiceDescriptorGroupTable...");
    
    // Write our row to PspServiceDescriptorGroupTable
    // Disable CR0.WP to allow writing to read-only kernel memory
    // NOTE: This will NOT work if HVCI is enabled!
    
    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
    ULONG_PTR cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000);  // Clear WP bit (bit 16)
    _mm_lfence();
    
    __try
    {
        DBG_PRINT("[AltSyscall] CR0.WP disabled, writing...");
        g_PspServiceDescriptorGroupTable->Rows[ALT_SYSCALL_SLOT_ID].DriverBase = g_DriverBase;
        g_PspServiceDescriptorGroupTable->Rows[ALT_SYSCALL_SLOT_ID].DispatchTable = g_AltSyscallDispatchTable;
        g_PspServiceDescriptorGroupTable->Rows[ALT_SYSCALL_SLOT_ID].Reserved = nullptr;
        DBG_PRINT("[AltSyscall] Write complete!");
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Restore CR0.WP before returning
        __writecr0(cr0);
        KeLowerIrql(oldIrql);
        
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, 
                  "Exception writing to PspServiceDescriptorGroupTable - HVCI may be blocking writes!");
        Memory::FreePool(g_AltSyscallDispatchTable);
        g_AltSyscallDispatchTable = nullptr;
        return STATUS_ACCESS_VIOLATION;
    }
    
    // Restore CR0.WP
    __writecr0(cr0);
    KeLowerIrql(oldIrql);
    
    DBG_PRINT("[AltSyscall] Installed dispatch table at slot %u", ALT_SYSCALL_SLOT_ID);
    
    // DON'T enable for all processes at startup - this causes system hangs!
    // Alt Syscall will only be enabled for Roblox when it starts via process callback
    // WalkActiveProcessesAndSetBits(true);  // DISABLED - causes system hang
    
    g_AltSyscallRegistered = true;
    
    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, 
              "Successfully initialized Windows 11 Alt Syscall hooks (PG-safe)");
    
    return STATUS_SUCCESS;
}
#endif

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
NTSTATUS
Initialize(_In_ SSDT_CALLBACK SsdtCallback)
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_SSDT_HOOK)
NTSTATUS
Initialize()
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_ALT_SYSCALL)
NTSTATUS
Initialize()
#endif
{
    PAGED_PASSIVE();

    NTSTATUS Status;

    if (g_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
    NT_ASSERT(SsdtCallback || MmIsAddressValid(SsdtCallback));

    g_SsdtCallback = SsdtCallback;
    Status = InitializeInfinityHook();
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_SSDT_HOOK)
    Status = InitializeSsdtHook();
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_ALT_SYSCALL)
    Status = InitializeAltSyscallHook();
#endif

    if (!NT_SUCCESS(Status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    g_initialized = true;

    return STATUS_SUCCESS;
}

void Cleanup()
{
#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
    CleanupInfinityHook();
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_SSDT_HOOK)
    CleanupSsdtHook();
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_ALT_SYSCALL)
    CleanupAltSyscallHook();
#endif
}

void Unitialize()
{
    PAGED_PASSIVE();

    if (!g_initialized)
    {
        return;
    }

    Cleanup();

    g_initialized = false;

    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Unitialized SyscallHook");
}

} // namespace SyscallHook