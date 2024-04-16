.code16
.section .text, "ax"
	movb $0xe, %ah
	movw $0, %si

loop:
	movb msg(%si), %al
	cmpb $0, %al
	je halt
	int $16
	addw $1, %si
	jmp loop

halt:
	hlt
	jmp halt

.section .rodata, "a"
msg:
	.asciz "HelloWorld!"

.section .bootsign, "a"
	.word 0xaa55
