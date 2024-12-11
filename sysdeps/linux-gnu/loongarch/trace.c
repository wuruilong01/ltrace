/*
 * This file is part of ltrace.
 * Copyright (C) 2024 Loongson Technology Corporation Limited.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <asm/ptrace.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "fetch.h"
#include "backend.h"
#include "proc.h"
#include "type.h"
#include "debug.h"

#define BRANCH_MASK 0xfc000000
#define OPCODE_JIRL 0x4c000000
#define OPCODE_B    0x50000000
#define OPCODE_BL   0x54000000
#define OPCODE_BEQ  0x58000000
#define OPCODE_BNE  0x5c000000
#define OPCODE_BLT  0x60000000
#define OPCODE_BGE  0x64000000
#define OPCODE_BLTU 0x68000000
#define OPCODE_BGEU 0x6c000000
#define OPCODE_BEQZ 0x40000000
#define OPCODE_BNEZ 0x44000000

void
get_arch_dep(struct process *proc)
{

}

/* Sign-extend the number in the bottom B bits of X to a 64-bit integer.
 * Requires 0 < B < 64 */
static inline int64_t sign_extend64(uint64_t X, unsigned B)
{
	assert(B > 0 && "Bit width can't be 0.");
	assert(B <= 64 && "Bit width out of range.");
	return (int64_t)(X << (64 - B)) >> (64 - B);
}

/* Return the bit field(s) from the most significant bit (msbit) to the
 * least significant bit (lsbit) of a 32-bit unsigned value. */
static inline uint32_t bits32(const uint32_t bits, const uint32_t msbit,
			      const uint32_t lsbit)
{
	assert(msbit < 32 && lsbit <= msbit);
	return (bits >> lsbit) & ((1u << (msbit - lsbit + 1)) - 1);
}

static int
loongarch_get_next_pcs(struct process *proc,
			arch_addr_t pc, arch_addr_t next_pcs[2])
{
	uint32_t insn;
	uint32_t op;
	uint32_t rj, imm;
	int64_t rj_value, signext_imm;
	int nr = 0;

	insn = (uint32_t)ptrace(PTRACE_PEEKTEXT, proc->pid, pc, 0);
	op = insn & BRANCH_MASK;

		switch (op) {
		case OPCODE_JIRL:
			rj = bits32(insn, 9, 5);
			rj_value = ptrace(PTRACE_PEEKUSER, proc->pid, rj, 0);
			imm = bits32(insn, 25, 10);
			signext_imm = sign_extend64(imm << 2, 18);
			next_pcs[nr++] = (arch_addr_t)(rj_value + signext_imm);
			next_pcs[nr++] = pc + 4;
			break;
		case OPCODE_B:
		case OPCODE_BL:
			imm = bits32(insn, 25, 10) + (bits32(insn, 9, 0) << 16);
			signext_imm = sign_extend64(imm << 2, 28);
			next_pcs[nr++] = pc + signext_imm;
			next_pcs[nr++] = pc + 4;
			break;
		case OPCODE_BEQ:
		case OPCODE_BNE:
		case OPCODE_BLT:
		case OPCODE_BGE:
		case OPCODE_BLTU:
		case OPCODE_BGEU:
			imm = bits32(insn, 25, 10);
			signext_imm = sign_extend64(imm << 2, 18);
			next_pcs[nr++] = pc + signext_imm;
			next_pcs[nr++] = pc + 4;
			break;
		case OPCODE_BEQZ:
		case OPCODE_BNEZ:
			imm = bits32(insn, 25, 10) + (bits32(insn, 4, 0) << 16);
			signext_imm = sign_extend64(imm << 2, 23);
			next_pcs[nr++] = pc + signext_imm;
			next_pcs[nr++] = pc + 4;
			break;
		default:
			next_pcs[nr++] = pc + 4;
			break;
		}
	if (nr <= 0 || nr > 2)
		goto fail;
	if (nr == 2) {
		if (next_pcs[1] == 0)
			goto fail;
	}
	if (next_pcs[0] == 0)
		goto fail;

	assert(nr == 1 || nr == 2);
	return nr;

fail:
	printf("nr=%d pc=%p\n", nr, pc);
	printf("next_pcs=%p %p\n", next_pcs[0], next_pcs[1]);

	return nr;

}

enum sw_singlestep_status
arch_sw_singlestep(struct process *proc, struct breakpoint *sbp,
		   int (*add_cb)(arch_addr_t, struct sw_singlestep_data *),
		   struct sw_singlestep_data *add_cb_data)
{
	int nr;
	arch_addr_t next_pcs[2] = {};
	arch_addr_t pc = get_instruction_pointer(proc);
	nr = loongarch_get_next_pcs(proc, pc, next_pcs);

	while (nr-- > 0) {
		arch_addr_t baddr =  next_pcs[nr];
		if (DICT_HAS_KEY(proc->leader->breakpoints, &baddr)) {
			fprintf(stderr, "skip %p %p\n", baddr, add_cb_data);
			continue;
		}

		if (add_cb(baddr, add_cb_data) < 0)
			return SWS_FAIL;
	}
	debug(1, "PTRACE_CONT");
	ptrace(PTRACE_CONT, proc->pid, 0, 0);
	return SWS_OK;
}

int
syscall_p(struct process *proc, int status, int *sysnum)
{
	if (WIFSTOPPED(status)
	    && WSTOPSIG(status) == (SIGTRAP | proc->tracesysgood)) {
		struct callstack_element *elem = NULL;
		if (proc->callstack_depth > 0)
			elem = proc->callstack + proc->callstack_depth - 1;
		/* sysnum in $a7(r11) on loongarch   */
		long int ret = ptrace(PTRACE_PEEKUSER, proc->pid,
				      GPR_BASE + 11, 0);
		if (ret == -1) {
			if (errno)
				return -1;
		}

		*sysnum = ret;

		if (elem != NULL && elem->is_syscall
		    && elem->c_un.syscall == *sysnum)
			return 2;

		if (*sysnum >= 0)
			return 1;
	}
	return 0;
}

size_t
arch_type_sizeof(struct process *proc, struct arg_type_info *info)
{
	if (proc == NULL)
		return (size_t)-2;

	switch (info->type) {
	case ARGTYPE_VOID:
		return 0;

	case ARGTYPE_CHAR:
		return 1;

	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
		return 2;

	case ARGTYPE_INT:
	case ARGTYPE_UINT:
		return 4;

	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_POINTER:
		return 8;

	case ARGTYPE_FLOAT:
		return 4;
	case ARGTYPE_DOUBLE:
		return 8;

	case ARGTYPE_ARRAY:
	case ARGTYPE_STRUCT:
		/* Use default value.  */
		return (size_t)-2;

	default:
		//assert(info->type != info->type);
		abort();
	}
}

size_t
arch_type_alignof(struct process *proc, struct arg_type_info *info)
{
	if (proc == NULL)
		return (size_t)-2;

	switch (info->type) {

	case ARGTYPE_CHAR:
		return 1;

	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
		return 2;

	case ARGTYPE_INT:
	case ARGTYPE_UINT:
		return 4;

	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_POINTER:
		return 8;

	case ARGTYPE_FLOAT:
		return 4;
	case ARGTYPE_DOUBLE:
		return 8;

	case ARGTYPE_ARRAY:
	case ARGTYPE_STRUCT:
		/* Use default value.  */
		return (size_t)-2;
	default:
		//assert(info->type != info->type);
		abort();
	}
}
