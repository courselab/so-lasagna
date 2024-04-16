MEMORY 
{
	BOOTROM (RXA) : ORIGIN = 0x7C00, LENGTH = 512
}

SECTIONS {
	.text   : { *(.text) } >BOOTROM
	.rodata : { *(.rodata) } >BOOTROM
	.bootsign 0x7dfe : { FILL(0x00); *(.bootsign) } >BOOTROM
	/DISCARD/ : { *(*) }
}



