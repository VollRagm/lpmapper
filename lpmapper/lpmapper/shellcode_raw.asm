; This file is solely to save the current shellcode
; It is not going to be included in the compilation process itself

sub rsp, 0x28
mov rax, [rdx+0xB8] 
mov r8, rdx
cmp dword [rax+18h], 8000200Bh
jnz 0x2D
mov rdx, [rax+0x20]
test rdx, rdx
jz 0x1E
mov rax, cr3
mov [rdx], rax
mov rcx, r8
and qword [r8+0x38], 0
xor edx, edx
and dword [r8+0x30], 0
mov rax, 0xFFFFFFFFFFFFFFFF ; IofCompleteRequest
call rax
xor rax, rax
add rsp, 0x28
retn
mov rdx, r8
add rsp, 28h
mov rax, 0xFFFFFFFFFFFFFFFF ; OriginalDispatch
jmp rax
