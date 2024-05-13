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

#include "bios.h"
#include "utils.h"

#define PROMPT "$ "		/* Prompt sign.      */
#define SIZE 20			/* Read buffer size. */

char buffer[SIZE];		/* Read buffer.      */

int main()
{
  clear();
  
  println  ("Boot Command 1.0");

  while (1)
    {
      print(PROMPT);		/* Show prompt.               */
      readln(buffer);		/* Read use input.            */

      if (buffer[0])		/* Execute built-in command.  */
	{
	  if (!strcmp(buffer,"help"))
	    println("A Beattles's song.");
	  else if (!strcmp(buffer,"clean"))
	  {
	  	__asm__
	  	(
			"pusha	\n"			/* Save all GP registers.              */
			"mov $0x0600, %ax \n"	/* Video service: scroll up.           */
			"mov $0x07, %bh	\n"		/* Attribute (background/foreground).  */
			"mov $0x00, %cx	\n"		/* Upper-left corner:   (0,0).         */
			"mov $0x184f, %dx	\n"	/* Botton-right corner: (24,79).       */
			"int $0x10	\n"		/* Call BIOS video service.            */

			"mov $0x2, %ah	\n"		/* Video service: set cursor position. */
			"mov $0x0, %bh	\n"		/* Select page number 0.               */
			"mov $0x0, %dx	\n"		/* Set position (0,0).                 */
			"int $0x10	\n"		/* Call BIOS video service.            */
			
			"popa	\n"
	  	);
	  }
	  else 
	    println("Unkown command.");
	}
    }
  
  return 0;

}
