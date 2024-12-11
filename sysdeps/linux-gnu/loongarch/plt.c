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
#include <gelf.h>
#include <stdbool.h>
#include "backend.h"
#include "proc.h"
#include "library.h"
#include "ltrace-elf.h"
#include "trace.h"

arch_addr_t
sym2addr(struct process *proc, struct library_symbol *sym)
{
	return sym->enter_addr;
}

GElf_Addr
arch_plt_sym_val(struct ltelf *lte, size_t ndx, GElf_Rela *rela)
{
	return lte->plt_addr + 32 + ndx * 16;
}


enum plt_status
arch_elf_add_plt_entry(struct process *proc, struct ltelf *lte,
		       const char *a_name, GElf_Rela *rela, size_t ndx,
		       struct library_symbol **ret)
{
#ifdef R_LARCH_IRELATIVE
	bool irelative = GELF_R_TYPE(rela->r_info) == R_LARCH_IRELATIVE;
#else
	bool irelative = false;
#endif

	if (irelative)
		return linux_elf_add_plt_entry_irelative(proc, lte, rela,
							 ndx, ret);

	return PLT_DEFAULT;
}
