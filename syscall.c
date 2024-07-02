/*
 *    SPDX-FileCopyrightText: 2024 Monaco F. J. <monaco@usp.br>
 *    SPDX-FileCopyrightText: 2024 marcelats <marcelats@usp.br>
 *   
 *    SPDX-License-Identifier: GPL-3.0-or-later
 *
 *  This file is a derivative work from SYSeg (https://gitlab.com/monaco/syseg)
 *  and contains modifications carried out by the following author(s):
 *  marcelats <marcelats@usp.br>
 */

/* The kernel registers a syscall handler at IVT entry 0x21. */

#include "bios1.h"
#include "bios2.h"

/* TyDOS syscall calling convetion: arguments in %ax, %dx and %cx.
   return value in %ax. See regparm(3) in function attributes section
   of the GCC manual.*/

#define _tycall_ __attribute__((regparm(3) ))

/* Print a string on the screen. */

int _tycall_ sys_open (const char* str)
{

}

int _tycall_ sys_write(const char* str)
{
  kwrite (str);
  return 0;
}

/*  Syscall 0 is invalid (should never be called)*/

int _tycall_ sys_invalid ()
{
  fatal ("Invalid syscall.");
  return 1;
}


/* This syscall should be called by the program upon termination. */

int _tycall_ sys_exit()
{
  return 0;
}
