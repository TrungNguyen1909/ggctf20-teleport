BITS 64

start:
	; int3
	mov rax, qword [rsp]
	push rbx
	lea rbx, [r15 + 0x100]
	mov qword [rbx], rax
	pop rbx
	ret
