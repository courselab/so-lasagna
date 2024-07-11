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

/* This source file implements the kernel entry function 'kmain' called
   by the bootloader, and the command-line interpreter. Other kernel functions
   were implemented separately in another source file for legibility. */

#include "bios1.h"		/* For kwrite() etc.            */
#include "bios2.h"		/* For kread() etc.             */
#include "kernel.h"		/* Essential kernel functions.  */
#include "kaux.h"		/* Auxiliary kernel functions.  */
#include "tydos.h"
#define DIR_ENTRY_LEN 32 	  /* Max file name length in bytes.           */
#define FS_SIGLEN 4               /* Signature length.                        */
/* Endereços onde o cabeçalho do sistema de arquivos e o buffer de diretório serão carregados */
#define FS_HEADER_ADDRESS   0x7C00 
#define DIR_BUFFER_ADDRESS  0x9000 
struct fs_header_t
{
  unsigned char  signature[FS_SIGLEN];    /* The file system signature.              */
  unsigned short total_number_of_sectors; /* Number of 512-byte disk blocks.         */
  unsigned short number_of_boot_sectors;  /* Sectors reserved for boot code.         */
  unsigned short number_of_file_entries;  /* Maximum number of files in the disk.    */
  unsigned short max_file_size;		  /* Maximum size of a file in blocks.       */
  unsigned int unused_space;              /* Remaining space less than max_file_size.*/
} __attribute__((packed));      /* Disable alignment to preserve offsets.  */

int syscall(int number, int arg1, int arg2, int arg3)
{
  __asm__("pusha \n");		/* We'll mess up with GP registers. */

  /* Our syscall ABI uses regparm(3) calling convention (see the section on
     x86 function attributes in the GCC manual. */
  
  int register bx __asm__("bx") = number; /* Syscall number (handler). */
  int register ax __asm__("ax") = arg1;	  /* First argument  in %ax.   */
  int register dx __asm__("dx") = arg2;	  /* Second argument in %dx.   */
  int register cx __asm__("cx") = arg3;	  /* Third argument in  %cx.   */

   __asm__
    (
     "int $0x21 \n"		/* Issue int $0x21.                    */
     "popa      \n "		/* Restore GP registers.               */
     );
}

/*  Write the string 'str' on the screen.*/

void puts(const char* str)
{
  syscall (SYS_WRITE, (int) str,0,0);
}

/* Kernel's entry function. */

void kmain(void)
{
  int i, j;
  
  register_syscall_handler();	/* Register syscall handler at int 0x21.*/

  splash();			/* Uncessary spash screen.              */

  shell();			/* Invoke the command-line interpreter. */
  
  halt();			/* On exit, halt.                       */
  
}

/* Tiny Shell (command-line interpreter). */

char buffer[BUFF_SIZE];
int go_on = 1;

void shell()
{
  int i;
  clear();
  kwrite ("MDOS\n");

  while (go_on)
    {

      /* Read the user input. 
	 Commands are single-word ASCII tokens with no blanks. */
      do
	{
	  kwrite(PROMPT);
	  kread (buffer);
	}
      while (!buffer[0]);

      /* Check for matching built-in commands */
      
      i=0;
      while (cmds[i].funct)
	{
	  if (!strcmp(buffer, cmds[i].name))
	    {
	      cmds[i].funct();
	      break;
	    }
	  i++;
	}

      /* If the user input does not match any built-in command name, just
	 ignore and read the next command. If we were to execute external
	 programs, on the other hand, this is where we would search for a 
	 corresponding file with a matching name in the storage device, 
	 load it and transfer it the execution. Left as exercise. */
      
      if (!cmds[i].funct)
	kwrite ("Try help to see the available commands\n");
    }
}


/* Array with built-in command names and respective function pointers. 
   Function prototypes are in kernel.h. */

struct cmd_t cmds[] =
  {
    {"help",    f_help},     /* Print a help message.       */
    {"quit",    f_quit},     /* Exit TyDOS.                 */
    {"exec",    f_exec},     /* Execute an example program. */
    {"list", 	f_list},     /* List the files.		    */		
    {0, 0}
  };

/* Build-in shell command: help. */

void f_help()
{
  kwrite ("Welcome to MDOS\n\n");
  kwrite ("   Try these commands:\n");
  kwrite ("      exec    (to execute an user program example)\n");
  kwrite ("	 list	 (to see the files)\n");
  kwrite ("      quit    (to exit MDOS)\n");
}

void f_quit()
{
  kwrite ("Close the QEMU window to exit");
  go_on = 0;
}

void printf(unsigned short i)
{
	char str[3];
	str[0] = i/10+'0';
	str[1] = i%10+'0';
	str[2] = '\0';
	kwrite(str);
}

void f_list()
{
	kwrite("Here are the files:\n");
	struct fs_header_t* fs_header = (struct fs_header_t*)0x7c00;
	// Calcula a coordenada inicial do setor da área de diretórios
  int dir_start_sector = 1 + header->number_of_boot_sectors;
// Calcula o número de setores a serem lidos para carregar todas as entradas de diretório
  int dir_sectors_to_read = header->number_of_file_entries * 32 / 512;
// Ponteiro para o pool de memória onde os dados do diretório serão carregados
  extern byte _MEM_POOL;
  void *dir_section_memory = (void *)&_MEM_POOL;
	// Carrega os setores do disco para a memória
  LerDisco(dir_start_sector, dir_sectors_to_read, dir_section_memory);
	unsigned short i;
	struct ponteiro* nome = (struct ponteiro*)((struct ponteiro*) 0x7c00 + fs_header->number_of_boot_sectors * 512);
	for (i=0; i < fs_header->number_of_file_entries; i++)
	{
		 // Obtém o nome do arquivo na posição atual da entrada de diretório
    char *name = dir_section_memory + i * 32;
		if(name[0])
		{
			puts(name);
			puts("\n");
		}
	}
}
/* Built-in shell command: example.

   Execute an example user program which invokes a syscall.

   The example program (built from the source 'prog.c') is statically linked
   to the kernel by the linker script (tydos.ld). In order to extend the
   example, and load and external C program, edit 'f_exec' and 'prog.c' choosing
   a different name for the entry function, such that it does not conflict with
   the 'main' function of the external program.  Even better: remove 'f_exec'
   entirely, and suppress the 'example_program' section from the tydos.ld, and
   edit the Makefile not to include 'prog.o' and 'libtydos.o' from 'tydos.bin'.

  */

//extern int main();
void f_exec()
{
  //main();			/* Call the user program's 'main' function. */
}
