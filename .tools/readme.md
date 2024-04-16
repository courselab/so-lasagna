<!--
   SPDX-FileCopyrightText: 2021 Monaco F. J. <monaco@usp.br>
  
   SPDX-License-Identifier: GPL-3.0-or-later

   This file is part of SYSeg, available at https://gitlab.com/monaco/syseg.
-->

 
 Directions for the exercise.
 ------------------------------

 TL;DR

 * `syseg-newfile`    creates a new file in your project
 * `syseg-export`     copy a source file from SYSeg into your project
 * `syseg-reuse`      annotate copyright and license information

 Use option `-h` for help.

 DETAILED INSTRUCTIONS

 For the sake of simplicity, let's say that the environment variables $SYSEG
 and $PROJ contain the paths to SYSeg and to you project, respectively.

 * This project was created using the SYSeg facilities designed specially for 
   this purpose. That procedure must have created your project directory and
   populated it with some bootstrap code that you are supposed to build upon.
   
   It should also have copied some auxiliary programs under the subdirectory

   `$PROJ/.tools`
   
   There you may find scripts that you should use to create new files, copy 
   source code from SYSeg, check your copyright and licensing information etc.

   You should always perform those tasks using the provided scripts so as to
   keep your project consistent with SYSeg specifications. That is important
   should you or your instructor decide to use SYSeg analysis tools. 

   In order to use the auxiliary scripts described in this file, you must have
   SYSeg installed in your computer. This means that, in addition to building
   SYSeg, you must have performed the `make install` step, as described in 
   `$SYSEG/doc/syseg.md`.


 * If you want to create a new file, use the proper script

   `$PROJ/.tools/syseg-newfile <destination-path>/<file-name>`

   The script should create the file, add some comments and, possibly, some 
   boilerplate code based on the file type (i.e. the file-name extension).

   Remember, you must have SYSeg installed (`make install`).
	       
 * SYSeg is free software and you may reuse its source code.

   Do not manually copy files from SYSeg source tree into your project's 
   directory. Instead, should you decide to reuse some SYSeg file in your
   programming exercise, use the script `syseg-export` like this

   ```
   $ cd $PROJ
   $ .tools/syseg-export $SYSEG/<path-to-file> ./<destination-path>
   ```
   The script will export the source file to the destination path, perform 
   necessary adjustments and annotate the copyright notice properly. 

   If your project has other authors besides you, you are expected to update
   the copyright information as described bellow.

 * If you have a co-author and they have a copy of the project in their own
   computer, they can easily update the copyright notice by issuing the
   following command
 
   ```
   $ cd $PROJ
   $ .tools/syseg-reuse <path-to-file>
   ```

   on their own computer. The script should resolve your co-author's name and
   the current year automatically (the script uses git config for that purpose).

   Alternatively, if you are to update the copyright info on behalf of your
   co-author, instead, you may run this command in your own computer

   ```
   $ cd $PROJ
   $ .tools/syseg-reuse -c <coauthor-name> -y $(date +%Y) <destination-path>/<file-name>
   ```

 * If you want to distribute your project under a different license that that
   of SYSeg, you may do so, as long as your other license does not conflict 
   with the terms of the original SYSeg license (if unsure, stick with the
   license).

   To add a license:

   ```
   $ .tools/syseg-reuse -l <alternative-valid-SPDX-license>
   ```

   Your license should also be added to the directory $PROJ/LICENSES. Run the
   following command to get it done automatically:

   ```
   $ .tools/syseg-reuse -d
   ```

