// raw_amd64.s：把"六个格子"模型落成真正的一小段汇编——
// 号码进 AX，六个参数进 DI/SI/DX/R10/R8/R9，执行 SYSCALL，
// 再把 rax 原样搬出来（【代码自定义】不做任何 errno 转换）。
//
// 对照：【Go 标准库实现】
// $(go env GOROOT)/src/internal/runtime/syscall/linux/asm_linux_amd64.s
// 里的实现多了末尾一段 CMPQ/NEGQ 转换（把负值拆成 -1 + errno），
// 本文件刻意省略该段，以观察 rax 的原始值。

#include "textflag.h"

// func rawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) int64
TEXT ·rawSyscall6(SB),NOSPLIT,$0-64
	MOVQ	trap+0(FP), AX
	MOVQ	a1+8(FP), DI
	MOVQ	a2+16(FP), SI
	MOVQ	a3+24(FP), DX
	MOVQ	a4+32(FP), R10
	MOVQ	a5+40(FP), R8
	MOVQ	a6+48(FP), R9
	SYSCALL
	MOVQ	AX, ret+56(FP)
	RET
