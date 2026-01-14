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

namespace Bypass
{
static wchar_t *g_BackupModulesList[] = {L"\\bin\\win64\\client.dll",           L"\\bin\\win64\\engine.dll",
                                         L"\\bin\\win64\\materialsystem2.dll",  L"\\bin\\win64\\inputsystem.dll",
                                         L"\\bin\\win64\\rendersystemdx11.dll", L"\\bin\\win64\\rendersystemvulkan.dll",
                                         L"\\bin\\win64\\inputsystem.dll",      L"\\bin\\win64\\scenesystem.dll"};

typedef struct _GAME_MODULE_ENTRY
{
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    ULONG_PTR BaseAddress;
    ULONG SizeOfImage;
    ULONG BaseOfCode;
    ULONG SizeOfCode;
    ULONG_PTR CopyBaseAddress;
    SIZE_T CopyAllocatedSize;

} GAME_MODULE_ENTRY, *PGAME_MODULE_ENTRY;

inline NPAGED_LOOKASIDE_LIST g_GameModulesLookasideList{};
inline LIST_ENTRY g_GameModulesList{};
inline Mutex::Resource g_GameModulesListLock;

typedef struct _PROTECTED_MODULE_ENTRY
{
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    ULONG_PTR AllocatedBase;
    SIZE_T RegionSize;

} PROTECTED_MODULE_ENTRY, *PPROTECTED_MODULE_ENTRY;

inline NPAGED_LOOKASIDE_LIST g_ProtectedModulesLookasideList{};
inline LIST_ENTRY g_ProtectedModulesList{};
inline Mutex::Resource g_ProtectedModulesListLock;

// Hidden regions - completely invisible to usermode (memory doesn't exist)
// Used for stealth injection where even query returns STATUS_INVALID_ADDRESS
typedef struct _HIDDEN_REGION_ENTRY
{
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    ULONG_PTR BaseAddress;
    SIZE_T RegionSize;
    HANDLE CreatorThreadId;  // Thread that created this region (for thread hijack tracking)

} HIDDEN_REGION_ENTRY, *PHIDDEN_REGION_ENTRY;

inline NPAGED_LOOKASIDE_LIST g_HiddenRegionsLookasideList{};
inline LIST_ENTRY g_HiddenRegionsList{};
inline Mutex::Resource g_HiddenRegionsListLock;

// Hidden threads - threads we create/hijack that should be invisible
typedef struct _HIDDEN_THREAD_ENTRY
{
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    HANDLE ThreadId;
    BOOLEAN IsHijacked;      // TRUE if this is a hijacked thread (don't hide, but spoof context)
    CONTEXT OriginalContext; // Saved context for hijacked threads

} HIDDEN_THREAD_ENTRY, *PHIDDEN_THREAD_ENTRY;

inline NPAGED_LOOKASIDE_LIST g_HiddenThreadsLookasideList{};
inline LIST_ENTRY g_HiddenThreadsList{};
inline Mutex::Resource g_HiddenThreadsListLock;

[[nodiscard]] NTSTATUS Initialize();
void Unitialize();

[[nodiscard]] NTSTATUS CreateGameModule(_In_ HANDLE ProcessId, _In_ PVOID MappedBase, _In_ SIZE_T MappedSize,
                                        _In_ PUNICODE_STRING MappedName);
[[nodiscard]] NTSTATUS CreateProtectedModule(_In_ HANDLE ProcessId, _In_ PVOID MappedBase, _In_ SIZE_T MappedSize);

[[nodiscard]] BOOLEAN IsInGameModuleMemoryRangeUnsafe(_In_ HANDLE ProcessId, _Out_opt_ PVOID *Object,
                                                      _In_ PVOID BaseAddress, _In_opt_ SIZE_T Range = 0ULL);
[[nodiscard]] BOOLEAN IsInProtectedModuleMemoryRangeUnsafe(_In_ HANDLE ProcessId, _Out_opt_ PVOID *Object,
                                                           _In_ PVOID BaseAddress, _In_opt_ SIZE_T Range = 0ULL);

[[nodiscard]] BOOLEAN IsInGameModuleMemoryRange(_In_ HANDLE ProcessId, _Out_opt_ PVOID *Object, _In_ PVOID BaseAddress,
                                                _In_opt_ SIZE_T Range = 0ULL);
[[nodiscard]] BOOLEAN IsInProtectedModuleMemoryRange(_In_ HANDLE ProcessId, _Out_opt_ PVOID *Object,
                                                     _In_ PVOID BaseAddress, _In_opt_ SIZE_T Range = 0ULL);

void EraseGameModules(_In_ HANDLE ProcessId);
void EraseProtectedModules(_In_ HANDLE ProcessId);

using ENUM_GAME_MODULES = BOOLEAN (*)(_In_ PGAME_MODULE_ENTRY);
using ENUM_PROTECTED_MODULES = BOOLEAN (*)(_In_ PPROTECTED_MODULE_ENTRY);

template <typename C = ENUM_GAME_MODULES> __forceinline BOOLEAN EnumGameModulesUnsafe(_In_ const C &Callback)
{
    NT_ASSERT(CURRENT_IRQL <= DISPATCH_LEVEL);

    LIST_ENTRY *listHead = &g_GameModulesList;

    if (IsListEmpty(listHead))
    {
        return FALSE;
    }

    PGAME_MODULE_ENTRY entry = nullptr;
    LIST_ENTRY *listEntry = listHead->Flink;
    BOOLEAN result = FALSE;

    while (listEntry != listHead)
    {
        entry = CONTAINING_RECORD(listEntry, GAME_MODULE_ENTRY, ListEntry);
        listEntry = listEntry->Flink;

        if (Callback(entry))
        {
            result = TRUE;
            break;
        }
    }
    return result;
}

template <typename C = ENUM_PROTECTED_MODULES> __forceinline BOOLEAN EnumProtectedModulesUnsafe(_In_ const C &Callback)
{
    NT_ASSERT(CURRENT_IRQL <= DISPATCH_LEVEL);

    LIST_ENTRY *listHead = &g_ProtectedModulesList;

    if (IsListEmpty(listHead))
    {
        return FALSE;
    }

    PPROTECTED_MODULE_ENTRY entry = nullptr;
    LIST_ENTRY *listEntry = listHead->Flink;
    BOOLEAN result = FALSE;

    while (listEntry != listHead)
    {
        entry = CONTAINING_RECORD(listEntry, PROTECTED_MODULE_ENTRY, ListEntry);
        listEntry = listEntry->Flink;

        if (Callback(entry))
        {
            result = TRUE;
            break;
        }
    }
    return result;
}

// Enumeration helpers for hidden regions
using ENUM_HIDDEN_REGIONS = BOOLEAN (*)(_In_ PHIDDEN_REGION_ENTRY);
using ENUM_HIDDEN_THREADS = BOOLEAN (*)(_In_ PHIDDEN_THREAD_ENTRY);

template <typename C = ENUM_HIDDEN_REGIONS> __forceinline BOOLEAN EnumHiddenRegionsUnsafe(_In_ const C &Callback)
{
    NT_ASSERT(CURRENT_IRQL <= DISPATCH_LEVEL);

    LIST_ENTRY *listHead = &g_HiddenRegionsList;

    if (IsListEmpty(listHead))
    {
        return FALSE;
    }

    PHIDDEN_REGION_ENTRY entry = nullptr;
    LIST_ENTRY *listEntry = listHead->Flink;
    BOOLEAN result = FALSE;

    while (listEntry != listHead)
    {
        entry = CONTAINING_RECORD(listEntry, HIDDEN_REGION_ENTRY, ListEntry);
        listEntry = listEntry->Flink;

        if (Callback(entry))
        {
            result = TRUE;
            break;
        }
    }
    return result;
}

template <typename C = ENUM_HIDDEN_THREADS> __forceinline BOOLEAN EnumHiddenThreadsUnsafe(_In_ const C &Callback)
{
    NT_ASSERT(CURRENT_IRQL <= DISPATCH_LEVEL);

    LIST_ENTRY *listHead = &g_HiddenThreadsList;

    if (IsListEmpty(listHead))
    {
        return FALSE;
    }

    PHIDDEN_THREAD_ENTRY entry = nullptr;
    LIST_ENTRY *listEntry = listHead->Flink;
    BOOLEAN result = FALSE;

    while (listEntry != listHead)
    {
        entry = CONTAINING_RECORD(listEntry, HIDDEN_THREAD_ENTRY, ListEntry);
        listEntry = listEntry->Flink;

        if (Callback(entry))
        {
            result = TRUE;
            break;
        }
    }
    return result;
}

// Hidden region functions - memory that doesn't exist to usermode
[[nodiscard]] NTSTATUS CreateHiddenRegion(_In_ HANDLE ProcessId, _In_ PVOID BaseAddress, _In_ SIZE_T RegionSize);
[[nodiscard]] BOOLEAN IsInHiddenRegion(_In_ HANDLE ProcessId, _In_ PVOID BaseAddress, _In_opt_ SIZE_T Range = 0ULL);
[[nodiscard]] BOOLEAN IsInHiddenRegionUnsafe(_In_ HANDLE ProcessId, _In_ PVOID BaseAddress, _In_opt_ SIZE_T Range = 0ULL);
void EraseHiddenRegions(_In_ HANDLE ProcessId);

// Hidden thread functions - for thread hijacking
[[nodiscard]] NTSTATUS CreateHiddenThread(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN IsHijacked);
[[nodiscard]] NTSTATUS SaveThreadContext(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ PCONTEXT Context);
[[nodiscard]] NTSTATUS GetSavedThreadContext(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _Out_ PCONTEXT Context);
[[nodiscard]] BOOLEAN IsHiddenThread(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId);
[[nodiscard]] BOOLEAN IsHijackedThread(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId);
void RemoveHiddenThread(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId);
void EraseHiddenThreads(_In_ HANDLE ProcessId);

} // namespace Bypass