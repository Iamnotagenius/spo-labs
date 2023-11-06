	default rel
	global 	test:function, \
			another:function, \
			stack:function, \
			print:function, \
			setChar:function, \
			testProc:function

	extern printf

section .text
test:
		push 	rbp
		mov 	rbp, rsp
		xor 	eax, eax
		add 	eax, edi
		add 	eax, esi
		add 	eax, esi
		pop 	rbp
		ret

another:
		push 	rbp
		mov 	rbp, rsp
		xor 	eax, eax
		add 	eax, edi
		movsx 	ebx, si
		cmp 	si, 0
		jle .J0
		add 	eax, ebx
		jmp .J1
.J0:
		sub 	eax, ebx
.J1:
		pop 	rbp
		ret

stack:
	push 	rbp
	mov 	rbp, rsp
	mov 	[rbp-1], dil
	mov 	[rbp-5], esi
	sub 	rsp, 16
	mov 	al, [rbp-1]
	movsx 	rax, al
	cmp 	rax, rsi
	sete 	al
	add 	rsp, 16
	pop 	rbp
	ret

print:
	mov 	rax, 1
	mov 	rdi, 1
	lea 	rsi, [S0]
	mov 	rdx, S0.len
	syscall
	lea 	rsi, [S1]
	mov 	rdx, S1.len
	mov 	rax, 1
	syscall
	ret

setChar:
	cmp 	rdx, rsi
	jge 	.L0
	mov 	edx, DWORD [rdi + rdx*4]
	mov 	rax, rdx
.L0:
	ret

testProc:
	push 	rbp
	mov 	rsi, rdi
	lea 	rdi, [S2]
	call 	printf WRT ..plt
	pop 	rbp
	ret

section .data
S0 		db 		"assembly is life", 10
.len 	equ 	$-S0
S1 		db 		"rip code is dope i want longer strings", 10
.len 	equ 	$-S1
S2 		db 		"from asm: %d", 10
