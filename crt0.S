.section .text
.global _start
_start:
   call get_ip_into_ax
   push %ax
   call main 
   hlt
get_ip_into_ax:
   mov (%sp), %ax
   ret
