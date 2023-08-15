; syscall.asm
.code

PUBLIC NtProtectVirtualMemory
PUBLIC NtAllocateVirtualMemory
PUBLIC jumper

NtProtectVirtualMemory proc
    mov esi, [rsp+30h]              ; Syscall ID for NtProtectVirtualMemory - move from stack into register
    mov eax, esi                    ; move Syscall ID into RAX register before syscall instruction is called
    mov r10, rcx
	syscall
	ret
NtProtectVirtualMemory endp

NtAllocateVirtualMemory proc
    ; Parameters passed in registers:
    ; RCX: ProcessHandle
    ; RDX: BaseAddress
    ; R8: ZeroBits
    ; R9: RegionSize
    ; R10: AllocationType
    ; R11: Protect

    ; --- Set up the syscall number for NtAllocateVirtualMemory ---
    ; The syscall number for NtAllocateVirtualMemory is 0x18
    mov rax, 18h
    mov r10, rcx

    ; --- Call NtAllocateVirtualMemory syscall ---
    syscall

    ; --- Check the return value in RAX ---
    ; The return value in RAX will be an NTSTATUS code
    ; If RAX is not 0, there was an error
    test rax, rax
    jnz syscall_failed

    ; Memory allocation succeeded
    ; Your code here to use the allocated memory

    ; Return with success status
    xor rax, rax   ; Set RAX to 0 (STATUS_SUCCESS)

    ; Return to the C++ caller
    ret

syscall_failed:
    ; Handle syscall failure here
    ; (Error code will be returned in RAX)
    ; Your code here to handle the failure

    ; Return with error status in RAX
    ret
NtAllocateVirtualMemory endp


jumper proc
    jmp rcx
    ret
jumper endp

end

