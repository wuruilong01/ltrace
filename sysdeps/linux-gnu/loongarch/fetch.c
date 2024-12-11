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

#include <elf.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <linux/uio.h>
#include "fetch.h"
#include "proc.h"
#include "type.h"
#include "value.h"
#include "arch.h"
#include "expr.h"

enum fetch_method {
	FETCH_NOP,
	FETCH_STACK,
	FETCH_GAR,
	FETCH_FAR,
};

struct small_struct_data_t {
	char fixed_member;
	char float_member;
	bool first_member_is_float;
};

struct fetch_context {
	struct user_pt_regs gregs;
	struct user_fp_state fpregs;
	unsigned int ngr;
	unsigned int nfr;
	arch_addr_t stack_pointer;
	arch_addr_t retval;
	bool in_varargs;
};

static int
loongarch_read_gregs(struct process *proc, struct user_pt_regs *regs)
{
	*regs = (struct user_pt_regs) {};
	struct iovec iovec;
	iovec.iov_base = regs;
	iovec.iov_len = sizeof *regs;
	return ptrace(PTRACE_GETREGSET, proc->pid, NT_PRSTATUS, &iovec) < 0
		? -1 : 0;
}

static int
loongarch_read_fregs(struct process *proc, struct user_fp_state  *regs)
{
	*regs = (struct user_fp_state) {};
	struct iovec iovec;
	iovec.iov_base = regs;
	iovec.iov_len = sizeof *regs;
	return ptrace(PTRACE_GETREGSET, proc->pid, NT_FPREGSET, &iovec) < 0
		? -1 : 0;
}

static void
get_array_member(struct arg_type_info *info,
		 struct small_struct_data_t *small_struct)
{
	long len;
	struct arg_type_info *array_type = info->u.array_info.elt_type;
	expr_eval_constant(info->u.array_info.length, &len);
	switch (array_type->type) {
	case ARGTYPE_STRUCT:
		break;
	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
		small_struct->float_member += len;
		break;
	default:
		if (small_struct->float_member > 0
		    && small_struct->fixed_member == 0)
			small_struct->first_member_is_float = true;
		small_struct->fixed_member += len;
		break;
	}
}

static void
get_struct_member(struct arg_type_info *info,
		  struct small_struct_data_t *small_struct)
{
	for (size_t i = 0; i < type_struct_size(info); i++) {
		struct arg_type_info *field = type_struct_get(info, i);
		assert(field != NULL);
		switch (field->type) {
		case ARGTYPE_STRUCT:
			get_struct_member(field, small_struct);
			break;
		case ARGTYPE_ARRAY:
			get_array_member(field, small_struct);
			break;
		case ARGTYPE_FLOAT:
		case ARGTYPE_DOUBLE:
			small_struct->float_member++;
			break;
		default:
			if (small_struct->float_member > 0
			    && small_struct->fixed_member == 0)
				small_struct->first_member_is_float = true;
			small_struct->fixed_member++;
			break;
		}
	}
}

static int
context_init(struct fetch_context *context, struct process *proc,
	     struct arg_type_info *ret_info)
{
	if (loongarch_read_gregs(proc, &context->gregs) < 0
	    || loongarch_read_fregs(proc, &context->fpregs) < 0)
		return -1;

	context->ngr = ARG_GAR_START;
	context->nfr = ARG_FAR_START;
	context->stack_pointer = (arch_addr_t)context->gregs.regs[3];
	context->retval = 0;
	context->in_varargs = false;

	return 0;
}

static int
fetch_gar(struct fetch_context *context, struct value *value,
	  size_t offset, size_t len)
{
	unsigned char *buf = value_get_raw_data(value);
	unsigned long u = context->gregs.regs[context->ngr++];
	memcpy(buf + offset, &u, len);

	return 0;
}

static int
fetch_far(struct fetch_context *context, struct value *value,
	  size_t offset, size_t len)
{
	unsigned char *buf = value_get_raw_data(value);
	uint64_t u = context->fpregs.fpr[context->nfr++];
	memcpy(buf + offset, &u, len);

	return 0;
}

static int
fetch_stack(struct fetch_context *context, struct value *value,
	    size_t align, size_t sz)
{
	if (align < 8)
		align = 8;
	size_t amount = ((sz + align - 1) / align) * align;
	uintptr_t sp = (uintptr_t) context->stack_pointer;
	sp = ((sp + align - 1) / align) * align;

	value_in_inferior(value, (arch_addr_t) sp);

	sp += amount;
	context->stack_pointer = (arch_addr_t) sp;

	return 0;
}

static void
classify_struct_argument(struct fetch_context const *context,
			 struct small_struct_data_t small_struct,
			 enum fetch_method methods[], size_t sz)
{
	/* "big" structs are dealt with in arch_fetch_arg_init(). */
	if (RLEN < sz && sz <= 2 * RLEN) {
		/* Only fixed-point members, the argument is passed in a
		 * pair of available GAR,with the low-order bits in the
		 *  lower-numbered GAR and the high-order bits in the
		 *  higher-numbered GAR. If only one GAR is available, the
		 *  low-order bits are in the GAR and the high-order bits
		 *  are on the stack, and passed on the stack if no GAR is
		 *  available. */
		if (small_struct.fixed_member > 0
		    && small_struct.float_member == 0) {
			if (context->ngr < ARG_GAR_END)
				methods[0] = methods[1] = FETCH_GAR;
			else if (context->ngr == ARG_GAR_END) {
				methods[0] = FETCH_GAR;
				methods[1] = FETCH_STACK;
			}
			else
				methods[0] = methods[1] = FETCH_STACK;
		} else if (small_struct.fixed_member == 0
			   && small_struct.float_member > 0) {
			/* The structure has one long double member or one
			 * double member and two adjacent float members or
			 * 3-4 float members. The argument is passed in a
			 * pair of available GAR, with the low-order bits
			 * in the lower-numbered GAR and the high-order bits
			 * in the higher-numbered GAR. If only one GAR is
			 * available, the low-order bits are in the GAR and
			 * the high-order bits are on the stack, and passed
			 * on the stack if no GAR is available. */
			if (small_struct.float_member > 2) {
				if (context->ngr < ARG_GAR_END)
					methods[0] = methods[1] = FETCH_GAR;
				else if (context->ngr == ARG_GAR_END) {
					methods[0] = FETCH_GAR;
					methods[1] = FETCH_STACK;
				}
				else
					methods[0] = methods[1] = FETCH_STACK;
			}
			if (small_struct.float_member == 1) {
				if (context->ngr < ARG_GAR_END)
					methods[0] = methods[1] = FETCH_GAR;
				else if (context->ngr == ARG_GAR_END) {
					methods[0] = FETCH_GAR;
					methods[1] = FETCH_STACK;
				}
				else
					methods[0] = methods[1] = FETCH_STACK;
			} else if (small_struct.float_member == 2) {
				/* The structure with two double members is
				 * passed in a pair of available FARs. If no a
				 * pair of available FARs, it’s passed in GARs.
				 * If only one GAR is available, the low-order
				 * bits are in the GAR and the high-order bits
				 * are on the stack, and passed on the stack if
				 * no GAR available, structure with one double
				 * member and one float member is same. */
				if (context->nfr < ARG_FAR_END
				    && !context->in_varargs) {
					methods[0] = methods[1] = FETCH_FAR;
				} else {
					if (context->ngr < ARG_GAR_END)
						methods[0] = methods[1] = FETCH_GAR;
					else if (context->ngr == ARG_GAR_END) {
						methods[0] = FETCH_GAR;
						methods[1] = FETCH_STACK;
					}
					else
						methods[0] = methods[1] = FETCH_STACK;
				}
			}
		} else if (small_struct.fixed_member > 0
			   && small_struct.float_member > 0) {
			/* The structure has one floating-point member and
			 * one fixed-point member. If one FAR and one GAR
			 * are available, the floating-point member of the
			 * structure is passed in the FAR, and the integer
			 * member of the structure is passed in the GAR;
			 * If no floating-point registers but two GARs are
			 * available, it’s passed in the two GARs; If only
			 * one GAR is available, the low-order bits are in
			 * the GAR and the high-order bits are on the stack;
			 * it’s passed on the stack if no GAR is available. */
			if (small_struct.fixed_member == 1
			    && small_struct.float_member == 1) {
				if (context->nfr <= ARG_FAR_END
				    && context->nfr <= ARG_FAR_END
				    && !context->in_varargs) {
					if (small_struct.first_member_is_float) {
						methods[0] = FETCH_FAR;
						methods[1] = FETCH_GAR;
					} else {
						methods[0] = FETCH_GAR;
						methods[1] = FETCH_FAR;
					}
				} else {
					if (context->ngr < ARG_GAR_END)
						methods[0] = methods[1] = FETCH_GAR;
					else if (context->ngr == ARG_GAR_END) {
						methods[0] = FETCH_GAR;
						methods[1] = FETCH_STACK;
					}
					else
						methods[0] = methods[1] = FETCH_STACK;
				}
			} else {
				/* Others, the argument is passed in a pair of
				 * available GAR, with the low-order bits in the
				 * lower-numbered GAR and the high-order bits in
				 * the higher-numbered GAR. If only one GAR is
				 * available, the low-order bits are in the GAR
				 * and the high-order bits are on the stack, and
				 * passed on the stack if no GAR is available. */
				if (context->ngr < ARG_GAR_END) {
					methods[0] = methods[1] = FETCH_GAR;
				}
				else if (context->ngr == ARG_GAR_END) {
					methods[0] = FETCH_GAR;
					methods[1] = FETCH_STACK;
				}
				else
					methods[0] = methods[1] = FETCH_STACK;
			}
		}
	} else if (sz <= RLEN) {
		/* The structure has only fixed-point members. If there
		 * is an available GAR, the structure is passed through
		 * the GAR by value passing; If no GAR is available,
		 * it’s passed on the stack. */
		if (small_struct.fixed_member > 0
		    && small_struct.float_member == 0) {
			if (context->ngr <= ARG_GAR_END)
				methods[0] =  FETCH_GAR;
			else
				methods[0] = FETCH_STACK;
		} else if (small_struct.fixed_member == 0
			   && small_struct.float_member > 0) {
			/* One floating-point member. The argument is passed
			 * in a FAR; If no FAR is available, the value is
			 * passed in a GAR; if no GAR is available, the value
			 * is passed on the stack. */
			if (small_struct.float_member == 1) {
				if (context->nfr <= ARG_FAR_END
				    && !context->in_varargs) {
					methods[0] = FETCH_FAR;
				} else {
					if (context->ngr <= ARG_GAR_END)
						methods[0] =  FETCH_GAR;
					else
						methods[0] = FETCH_STACK;
				}
			} else if (small_struct.float_member == 2) {
				/* Two floating-point members. argument is
				 * passed in a pair of available FAR, with
				 * the low-order float member bits in the
				 * lower-numbered FAR and the high-order
				 * float member bits in the higher-numbered
				 * FAR. If the number of available FAR is
				 * less than 2, it’s passed in a GAR, and
				 * passed on stack if no GAR available. */
				if (context->nfr < ARG_FAR_END
				    && !context->in_varargs) {
					methods[0] = methods[1] = FETCH_FAR;
				} else {
					if (context->ngr <= ARG_GAR_END)
						methods[0] =  FETCH_GAR;
					else
						methods[0] = FETCH_STACK;
				}
			}
		} else if (small_struct.fixed_member > 0
			 && small_struct.float_member == 1) {
			/* Multiple fixed-point members. If there are
			 * available GAR, the structure passed in a GAR,
			 * and passed on the stack if no GAR is available. */
			if (small_struct.fixed_member > 1) {
				if (context->ngr <= ARG_GAR_END)
					methods[0] =  FETCH_GAR;
				else
					methods[0] = FETCH_STACK;
			} else if (small_struct.fixed_member == 1) {
				/* Only one fixed-point member. If one FAR
				 * and one GAR are available, floating-point
				 * member of the structure is passed in FAR,
				 * and the integer member is passed in GAR;
				 * If no floating-point register but one GAR
				 * is available, it’s passed in GAR; If no
				 * GAR is available, it’s passed on stack. */
				if (context->nfr <= ARG_FAR_END
				    && context->nfr <= ARG_FAR_END
				    && !context->in_varargs) {
					if (small_struct.first_member_is_float) {
						methods[0] = FETCH_FAR;
						methods[1] = FETCH_GAR;
					} else {
						methods[0] = FETCH_FAR;
						methods[1] = FETCH_GAR;
					}
				} else {
					if (context->ngr <= ARG_GAR_END)
						methods[0] =  FETCH_GAR;
					else
						methods[0] = FETCH_STACK;
				}
			}
		}
	}
}

static int
classify_argument(struct fetch_context const *context,
		  struct process *proc, struct arg_type_info *info,
		  enum fetch_method methods[])
{
	struct small_struct_data_t  small_struct = {0, 0, false};
	size_t sz = type_sizeof(proc, info);
	if (sz == (size_t) -1)
		return -1;

	switch (info->type) {
	case ARGTYPE_VOID:
		return -1;

	case ARGTYPE_STRUCT:
		get_struct_member (info, &small_struct);
		classify_struct_argument(context, small_struct, methods, sz);
		return 0;
	case ARGTYPE_POINTER:
	case ARGTYPE_ARRAY:
	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_CHAR:
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
		if (context->ngr <= ARG_GAR_END)
			methods[0] = FETCH_GAR;
		else
			methods[0] = FETCH_STACK;
		return 0;
	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
		if (context->nfr <= ARG_FAR_END && !context->in_varargs)
			methods[0] = FETCH_FAR;
		else if (context->ngr <= ARG_GAR_END)
			methods[0] = FETCH_GAR;
		else
			methods[0] = FETCH_STACK;
		return 0;
	}

	assert(!"Failed to classify argument.");
	abort();
}


static int
classify_return_value(struct fetch_context const *context,
		      struct process *proc, struct arg_type_info *info,
		      enum fetch_method methods[])
{
	struct small_struct_data_t  small_struct = {0, 0, false};
	size_t sz = type_sizeof(proc, info);
	if (sz == (size_t) -1)
		return -1;

	switch (info->type) {
	case ARGTYPE_VOID:
		return 0;
	case ARGTYPE_STRUCT:
		get_struct_member (info, &small_struct);
		/* sz <= RLEN */
		if (sz <= RLEN) {
			/* The structure has only fixed-point members.
			 * passed on $v0. */
			if (small_struct.fixed_member > 0
			    && small_struct.float_member == 0)
				methods[0] =  FETCH_GAR;
			/* The structure has only floating-point members. */
			else if (small_struct.fixed_member == 0
				 && small_struct.float_member > 0) {
				/* One floating-point member. passed on $fv0 */
				if (small_struct.float_member == 1)
					methods[0] =  FETCH_FAR;
				/* Two floating-point members. passed on $fv0
				 * and $fv1 */
				else if (small_struct.float_member == 2) {
					methods[0] =  FETCH_FAR;
					methods[1] =  FETCH_FAR;
				}
			}
			/* The structure has both fixed-point and floating
			 * point members */
			else if (small_struct.fixed_member > 0
				 && small_struct.float_member == 1) {
				/* Multiple fixed-point members. passed on
				 * $v0. */
				if (small_struct.fixed_member > 1)
					methods[0] =  FETCH_GAR;
				/* Only one fixed-point member. float-point
				 * member is passed on $fv0, fixed-point member
				 * is passed on $v0. */
				else if (small_struct.fixed_member == 1) {
					if (small_struct.first_member_is_float) {
						methods[0] =  FETCH_FAR;
						methods[1] =  FETCH_GAR;
					} else {
						methods[0] =  FETCH_GAR;
						methods[1] =  FETCH_FAR;
					}
				}
			}
		}
		/* RLEN < sz && sz <= 2 * RLEN */
		else if (RLEN < sz && sz <= 2 * RLEN) {
			/* Only fixed-point members, passed on $v0 and $v1 */
			if (small_struct.fixed_member > 0
			    && small_struct.float_member == 0) {
				methods[0] =  FETCH_GAR;
				methods[1] =  FETCH_GAR;
			}
			/* Only floating-point members. */
			else if (small_struct.fixed_member == 0
				 && small_struct.float_member > 0) {
				/* The structure has one long double member
				 * or one double member and two adjacent
				 * float members or 3-4 float members. passed
				 * on $v0 and $v1. */
				if (small_struct.float_member == 1
				    || small_struct.float_member > 2) {
					methods[0] =  FETCH_GAR;
					methods[1] =  FETCH_GAR;
				}
				/* The structure two double member, passed on
				 * $fv0 and $fv1. */
				if (small_struct.float_member == 2) {
					methods[0] =  FETCH_FAR;
					methods[1] =  FETCH_FAR;
				}
			}
			/* Both fixed-point and floating-point members. */
			else if (small_struct.fixed_member > 0
				 && small_struct.float_member > 0) {
				/* The structure has one floating-point member
				 * and one fixed-point member. float-point
				 * member is passed on $fv0, fixed-point member
				 * is passed on $v0.*/
				if (small_struct.fixed_member == 1
				    && small_struct.float_member == 1) {
					if (small_struct.first_member_is_float) {
						methods[0] =  FETCH_FAR;
						methods[1] =  FETCH_GAR;
					} else {
						methods[0] =  FETCH_GAR;
						methods[1] =  FETCH_FAR;
					}
				}
				/* Others, passed on $v0 and $v1. */
				else {
					methods[0] =  FETCH_GAR;
					methods[1] =  FETCH_GAR;
				}
			}
		}
		return 0;
	case ARGTYPE_POINTER:
	case ARGTYPE_ARRAY:
	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_CHAR:
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
		methods[0] = FETCH_GAR;
		return 0;
	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
		methods[0] = FETCH_FAR;
		return 0;
	}

	assert(!"Failed to classify retval.");
	abort();
}

static int
fetch_argument(struct fetch_context *context,
	  struct process *proc, struct arg_type_info *info,
	  struct value *value, enum fetch_method method,
	  size_t offset, size_t len)
{
	switch (method) {
	case FETCH_NOP:
		return 0;

	case FETCH_STACK:
		return fetch_stack(context, value, RLEN, RLEN);

	case FETCH_GAR:
		return fetch_gar(context, value, offset, len);

	case FETCH_FAR:
		return fetch_far(context, value, offset, len);

	}

	assert(!"Don't know how to fetch argument.");
	abort();
}

static int
fetch_return_value(struct fetch_context *context, struct process *proc,
		   struct arg_type_info *info, struct value *value,
		   enum fetch_method method, size_t offset, size_t len)
{

	switch (method) {
	case FETCH_NOP:
		return 0;
	case FETCH_STACK:
		return 0;

	case FETCH_GAR:
		return fetch_gar(context, value, offset, len);

	case FETCH_FAR:
		return fetch_far(context, value, offset, len);

	}

	assert(!"Don't know how to fetch retval.");
	abort();
}

struct fetch_context *
arch_fetch_arg_clone(struct process *proc, struct fetch_context *context)
{
	struct fetch_context *ret = malloc(sizeof(*ret));

	if (ret == NULL)
		return NULL;
	return memcpy(ret, context, sizeof(*ret));
}

struct fetch_context *
arch_fetch_arg_init(enum tof type, struct process *proc,
		    struct arg_type_info *ret_info)
{
	struct fetch_context *context = malloc(sizeof *context);
	if (context == NULL || context_init(context, proc, ret_info) < 0) {
fail:
		free(context);
		return NULL;
	}

	size_t sz = type_sizeof(proc, ret_info);
	if (sz == (size_t) -1)
		goto fail;

	if (sz > 2 * RLEN) {
		/* The reference of the return value is stored in GAR a0
		 * if the size of return value is larger than 2*GRLEN bits */
		context->retval = (arch_addr_t) context->gregs.regs[context->ngr++];
	}

	return context;
}

int
arch_fetch_arg_next(struct fetch_context *context, enum tof type,
		    struct process *proc, struct arg_type_info *info,
		    struct value *value)
{
	enum fetch_method methods[2] = {FETCH_NOP, FETCH_NOP};
	size_t len = RLEN;
	size_t sz = type_sizeof(proc, info);
	if (sz == (size_t) -1)
		return -1;
	if (sz > 2 * RLEN) {
		sz = 8;
		value_pass_by_reference(value);
		if (context->ngr <= ARG_GAR_END)
			methods[0] =  FETCH_GAR;
		else
			methods[0] = FETCH_STACK;
	} else {
		if (classify_argument(context, proc, info, methods) != 0)
			return -1;
	}

	if (value_reserve(value, sz) == NULL)
		return -1;

	if (methods[1] == FETCH_NOP) {
		fetch_argument(context, proc, info, value, methods[0], 0, RLEN);
	} else {
		if (sz <= RLEN)
			len = RLEN / 2;

		fetch_argument(context, proc, info, value, methods[0], 0, len);
		fetch_argument(context, proc, info, value, methods[1], len, len);
	}

	return 0;
}

int
arch_fetch_retval(struct fetch_context *context, enum tof type,
		  struct process *proc, struct arg_type_info *info,
		  struct value *value)
{
	size_t len = RLEN;
	size_t sz = type_sizeof(proc, info);
	if (sz == (size_t) -1)
		return -1;

	if (type == LT_TOF_FUNCTIONR) {
		enum fetch_method methods[2] = {FETCH_NOP, FETCH_NOP};
		if (context->retval != 0) {
			/* return value is larger than 2*GRLEN
			 * was extracted when in fetch init. */
			value_in_inferior(value, context->retval);
			return 0;
		}

		if (context_init(context, proc, info) < 0)
			return -1;

		if (classify_return_value(context, proc, info, methods) != 0)
			return -1;

		if (value_reserve(value, sz) == NULL)
			return -1;

		if (methods[1] == FETCH_NOP) {
			fetch_return_value(context, proc, info, value,
					    methods[0], 0, RLEN);
		} else {
			if (sz <= RLEN)
				len = RLEN / 2;

			fetch_return_value(context, proc, info, value,
					   methods[0], 0, len);
			fetch_return_value(context, proc, info, value,
					    methods[1], len, len);
		}

	}
	/* SYSCALLR,return value in GAR a0 */
	else if (type == LT_TOF_SYSCALLR)
		value_in_inferior(value, (arch_addr_t) context->gregs.regs[4]);

	return 0;
}

void
arch_fetch_arg_done(struct fetch_context *context)
{
	if (context != NULL)
		free(context);
}

int
arch_fetch_param_pack_start(struct fetch_context *context,
			    enum param_pack_flavor ppflavor)
{
	if (ppflavor == PARAM_PACK_VARARGS)
		context->in_varargs = true;
	return 0;
}

void
arch_fetch_param_pack_end(struct fetch_context *context)
{
	context->in_varargs = false;
}
