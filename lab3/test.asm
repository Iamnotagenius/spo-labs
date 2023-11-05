	global 	test, another, stack

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
	movzx 	eax, dil
	cmp 	eax, esi
	sete 	al
	add 	rsp, 16
	pop 	rbp
	ret
