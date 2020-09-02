BITS 64

start:
	; int3
	mov rax, 0x4141414141414141 ; To be replaced
	push rbx
	lea rbx, [r15 + 0x100]
	mov rax, qword [rax]
	mov qword [rbx], rax
	pop rbx
	ret
