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

#include "config.h"
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <linux/uio.h>
#include "proc.h"
#include "common.h"
#include "backend.h"

#if (!defined(PTRACE_PEEKUSER) && defined(PTRACE_PEEKUSR))
# define PTRACE_PEEKUSER PTRACE_PEEKUSR
#endif

#if (!defined(PTRACE_POKEUSER) && defined(PTRACE_POKEUSR))
# define PTRACE_POKEUSER PTRACE_POKEUSR
#endif

void *
get_instruction_pointer(struct process *proc)
{
	return (void *)ptrace(PTRACE_PEEKUSER, proc->pid, PC, 0);
}

void
set_instruction_pointer(struct process *proc, void *addr)
{
	ptrace(PTRACE_POKEUSER, proc->pid, PC, addr);
}

void *
get_stack_pointer(struct process *proc)
{
	return (void *)ptrace(PTRACE_PEEKUSER, proc->pid, GPR_BASE + 3, 0);
}

void *
get_return_addr(struct process *proc, void *stack_pointer)
{
	return (void *)ptrace(PTRACE_PEEKUSER, proc->pid, GPR_BASE + 1, 0);
}
