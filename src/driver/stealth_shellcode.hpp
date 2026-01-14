 /******************************************************************************
    Stealth Injection Shellcode for Thread Hijacking
    
    The shellcode is defined in stealth_shellcode.asm and assembled with ml64.
    This header provides the HIJACK_CONTEXT structure and extern declarations.
    
    Build: ml64.exe /c /Fo stealth_shellcode.obj stealth_shellcode.asm
 ******************************************************************************/
#pragma once

namespace StealthShellcode
{

//------------------------------------------------------------------------------
// HIJACK_CONTEXT structure - passed to shellcode via RCX
// Must match the offsets in stealth_shellcode.asm exactly!
//------------------------------------------------------------------------------
#pragma pack(push, 1)
typedef struct _HIJACK_CONTEXT
{
    // === Synchronization (offset 0x00) ===
    volatile LONG Lock;              // 0x00: Spinlock for kernel synchronization
    volatile LONG Completed;         // 0x04: Set to 1 when done
    volatile LONG Result;            // 0x08: DllMain return value (0 = fail, 1 = success)
    volatile LONG ErrorCode;         // 0x0C: Error code if failed

    // === Original thread state to restore (offset 0x10) ===
    ULONG64 OriginalRip;             // 0x10: Where to return after shellcode
    ULONG64 OriginalRsp;             // 0x18: Original stack pointer
    ULONG64 OriginalRax;             // 0x20: Original RAX
    ULONG64 OriginalRbx;             // 0x28: Original RBX
    ULONG64 OriginalRcx;             // 0x30: Original RCX
    ULONG64 OriginalRdx;             // 0x38: Original RDX
    ULONG64 OriginalRsi;             // 0x40: Original RSI
    ULONG64 OriginalRdi;             // 0x48: Original RDI
    ULONG64 OriginalRbp;             // 0x50: Original RBP
    ULONG64 OriginalR8;              // 0x58: Original R8
    ULONG64 OriginalR9;              // 0x60: Original R9
    ULONG64 OriginalR10;             // 0x68: Original R10
    ULONG64 OriginalR11;             // 0x70: Original R11
    ULONG64 OriginalR12;             // 0x78: Original R12
    ULONG64 OriginalR13;             // 0x80: Original R13
    ULONG64 OriginalR14;             // 0x88: Original R14
    ULONG64 OriginalR15;             // 0x90: Original R15
    ULONG64 OriginalRflags;          // 0x98: Original RFLAGS

    // === XMM registers - volatile in x64 ABI (offset 0xA0) ===
    DECLSPEC_ALIGN(16) UCHAR OriginalXmm0[16];  // 0xA0
    DECLSPEC_ALIGN(16) UCHAR OriginalXmm1[16];  // 0xB0
    DECLSPEC_ALIGN(16) UCHAR OriginalXmm2[16];  // 0xC0
    DECLSPEC_ALIGN(16) UCHAR OriginalXmm3[16];  // 0xD0
    DECLSPEC_ALIGN(16) UCHAR OriginalXmm4[16];  // 0xE0
    DECLSPEC_ALIGN(16) UCHAR OriginalXmm5[16];  // 0xF0

    // === PE Image info (offset 0x100) ===
    ULONG64 ImageBase;               // 0x100: Mapped image base
    ULONG64 ImageSize;               // 0x108: Image size
    ULONG64 EntryPointRva;           // 0x110: AddressOfEntryPoint RVA
    ULONG64 RelocDirRva;             // 0x118: Relocation directory RVA
    ULONG64 RelocDirSize;            // 0x120: Relocation directory size
    ULONG64 ImportDirRva;            // 0x128: Import directory RVA
    ULONG64 ImportDirSize;           // 0x130: Import directory size
    ULONG64 OriginalImageBase;       // 0x138: Original PE ImageBase for delta calculation
    ULONG64 TlsDirRva;               // 0x140: TLS directory RVA
    ULONG64 TlsDirSize;              // 0x148: TLS directory size

    // === Required function pointers (offset 0x150) ===
    ULONG64 pLoadLibraryA;           // 0x150: kernel32!LoadLibraryA
    ULONG64 pGetProcAddress;         // 0x158: kernel32!GetProcAddress
    ULONG64 pNtFlushInstructionCache;// 0x160: ntdll!NtFlushInstructionCache
    ULONG64 pLdrpHandleTlsData;      // 0x168: ntdll!LdrpHandleTlsData (optional)
    ULONG64 pRtlAddVectoredExceptionHandler; // 0x170: ntdll!RtlAddVectoredExceptionHandler (optional)

} HIJACK_CONTEXT, *PHIJACK_CONTEXT;
#pragma pack(pop)

static_assert(sizeof(HIJACK_CONTEXT) == 0x178, "HIJACK_CONTEXT size mismatch with ASM");

//------------------------------------------------------------------------------
// Extern declarations for the assembled shellcode
// Defined in stealth_shellcode.obj (assembled from stealth_shellcode.asm)
//------------------------------------------------------------------------------
extern "C" void HijackShellcodeV2(PHIJACK_CONTEXT Context);
extern "C" void HijackShellcodeV2End();

// Calculate shellcode size at runtime from the linker symbols
inline SIZE_T GetShellcodeSize()
{
    return reinterpret_cast<ULONG_PTR>(&HijackShellcodeV2End) - 
           reinterpret_cast<ULONG_PTR>(&HijackShellcodeV2);
}

// Get pointer to the shellcode function (in kernel memory - must be copied to usermode)
inline PVOID GetShellcodeAddress()
{
    return reinterpret_cast<PVOID>(&HijackShellcodeV2);
}

// Copy shellcode to usermode buffer
inline NTSTATUS CopyShellcodeToUsermode(PVOID UserBuffer, SIZE_T BufferSize)
{
    SIZE_T shellcodeSize = GetShellcodeSize();
    if (BufferSize < shellcodeSize)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    RtlCopyMemory(UserBuffer, GetShellcodeAddress(), shellcodeSize);
    return STATUS_SUCCESS;
}

} // namespace StealthShellcode
