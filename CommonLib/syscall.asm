;*******************************************************************************
;
;  (C) COPYRIGHT AUTHORS, 2016
;
;  TITLE:       SYSCALL.ASM
;
;  VERSION:     1.00
;
;  DATE:        11 July 2016
;
;  Syscall gate implementation.
;
; THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
; ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
; TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
; PARTICULAR PURPOSE.
;
;*******************************************************************************/
public NtSyscall

_TEXT$00 segment para 'CODE'

	ALIGN 16
	PUBLIC NtSyscall

; param 1 (rcx) service ID
; param 2 (rdx) service arguments count
; param 3 (r8) pointer to array of arguments

NtSyscall PROC
	sub rsp, 0100h	; UPD : INCASE THAT YOU USE AN ARRAY ON STACK AS ARGUMENTS
	cmp rdx, 5
	jl @@nostack
	
	sub rdx, 4
	xor r9, r9
@@fillstack:
	mov rax,[r9*8+r8+020h]
	mov [r9*8+rsp+028h], rax
	inc r9
	dec rdx
	jne @@fillstack

@@nostack:
	mov r10, r8
	mov rax, rcx
	mov rcx, [r10]
	mov rdx, [r10+08h]
	mov r8, [r10+10h]
	mov r9, [r10+18h]
	mov r10, rcx
	syscall

	add rsp, 0100h
	ret
NtSyscall ENDP

_TEXT$00 ENDS
	
END