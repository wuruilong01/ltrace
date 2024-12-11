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

#ifndef LTRACE_LOONGARCH_ARCH_H
#define LTRACE_LOONGARCH_ARCH_H


/* | 31                             15 | 14          0 |
 * | 0 0 0 0 0 0 0 0 0 0 1 0 1 0 1 0 0 |      code     | */
#define BREAKPOINT_VALUE { 0x00, 0x00, 0x2A, 0x00 }
#define BREAKPOINT_LENGTH   4
#define DECR_PC_AFTER_BREAK 0
#define ARCH_ENDIAN_LITTLE

#define LT_ELFCLASS	ELFCLASS64
#define LT_ELF_MACHINE	EM_LOONGARCH

#define ARCH_HAVE_SIZEOF
#define ARCH_HAVE_ALIGNOF
#define ARCH_HAVE_ADD_PLT_ENTRY
#define ARCH_HAVE_SW_SINGLESTEP
#define ARCH_HAVE_FETCH_ARG
#define ARCH_HAVE_FETCH_PACK

#define RLEN		8
#define ARG_GAR_START	4
#define ARG_GAR_END	11
#define ARG_FAR_START	0
#define ARG_FAR_END	7

#endif /* LTRACE_LOONGARCH_ARCH_H */
