/*
 *    SPDX-FileCopyrightText: 2021 Monaco F. J. <monaco@usp.br>
 *    SPDX-FileCopyrightText: 2024 marcelats <marcelats@usp.br>
 *   
 *    SPDX-License-Identifier: GPL-3.0-or-later
 *
 *  This file is a derivative work from SYSeg (https://gitlab.com/monaco/syseg)
 *  and contains modifications carried out by the following author(s):
 *  marcelats <marcelats@usp.br>
 */

/* This is the linker script used to build user programs. */

OUTPUT_FORMAT(binary)		/* Output flat binary (no structure). */
SECTIONS
{
	PRG_LOAD_ADDR = 0xFE00;	/* Program load address.              */
	
        . = PRG_LOAD_ADDR;
	
        .bin :
	{
	  crt0.o (.text)
          *.o   (.text .data .bss .rodata) /* Command line objects. */
	  libtydos.o (.text .data .bss .rodata) /* Runtime library. */
	}		
}
INPUT(libtydos.a)		/* Link with the TyDOS user library. */




