/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011-2018 Robert N. M. Watson
 * All rights reserved.
 * Copyright (c) 2016-2020 Andrew Turner
 * Copyright (c) 2020 John Baldwin
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and
 * the University of Cambridge Computer Laboratory under DARPA/AFRL
 * contract (FA8750-10-C-0237) ("CTSRD"), as part of the DARPA CRASH
 * research programme.
 *
 * Portions of this software were developed by SRI International and
 * the University of Cambridge Computer Laboratory (Department of
 * Computer Science and Technology) under DARPA contract
 * HR0011-18-C-0016 ("ECATS"), as part of the DARPA SSITH research
 * programme.
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef	_CHERIREG_H_
#define	_CHERIREG_H_

#if defined(__FreeBSD__)
/* Bring in all the FreeBSD definitions */
#include_next <cheri/cherireg.h>
#endif

#if defined(__aarch64__)
/*
 * CHERI ISA-defined constants for capabilities -- suitable for inclusion from
 * assembly source code.
 */
#define	CHERITEST_CHERI_PERM_SW0				(1 << 2)	/* 0x00000004 */
#define	CHERITEST_CHERI_PERM_SW1				(1 << 3)	/* 0x00000008 */
#define	CHERITEST_CHERI_PERM_SW2				(1 << 4)	/* 0x00000010 */
#define	CHERITEST_CHERI_PERM_SW3				(1 << 5)	/* 0x00000020 */

/*
 * Macros defining initial permission sets:
 *
 * CHERITEST_CHERI_PERMS_SWALL: Mask of all available software-defined permissions
 * CHERI_PERMS_HWALL: Mask of all available hardware-defined permissions
 */
#define	CHERITEST_CHERI_PERMS_SWALL							\
	(CHERITEST_CHERI_PERM_SW0 | CHERITEST_CHERI_PERM_SW1 |	\
	CHERITEST_CHERI_PERM_SW2 | CHERITEST_CHERI_PERM_SW3)

/*
 * Basic userspace permission mask; CHERI_PERM_EXECUTE will be added for
 * executable capabilities (pcc); CHERI_PERM_STORE, CHERI_PERM_STORE_CAP,
 * and CHERI_PERM_STORE_LOCAL_CAP will be added for data permissions (ddc).
 */
#define	CHERITEST_CHERI_PERMS_USERSPACE								\
	(CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |	\
	CHERI_PERM_INVOKE |												\
	(CHERITEST_CHERI_PERMS_SWALL & ~CHERI_PERM_SW_VMEM))

#define	CHERITEST_CHERI_PERMS_USERSPACE_CODE					\
	(CHERITEST_CHERI_PERMS_USERSPACE | CHERI_PERM_EXECUTE |		\
	ARM_CAP_PERMISSION_EXECUTIVE | CHERI_PERM_LOAD_MUTABLE)

#define	CHERITEST_CHERI_PERMS_USERSPACE_SEALCAP					\
	(CHERI_PERM_GLOBAL | CHERI_PERM_SEAL | CHERI_PERM_UNSEAL)

#define CHERITEST_CHERI_PERMS_USERSPACE								\
	(CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |	\
	CHERI_PERM_INVOKE |												\
	(CHERITEST_CHERI_PERMS_SWALL & ~CHERI_PERM_SW_VMEM))

#define CHERITEST_CHERI_PERMS_USERSPACE_DATA				\
	(CHERITEST_CHERI_PERMS_USERSPACE | CHERI_PERM_STORE |	\
	CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP |		\
	CHERI_PERM_LOAD_MUTABLE)

#define	CHERITEST_CHERI_CAP_USER_DATA_PERMS	CHERITEST_CHERI_PERMS_USERSPACE_DATA

/*
 * The CHERI object-type space is split between userspace and kernel,
 * permitting kernel object references to be delegated to userspace (if
 * desired).  Currently, we provide 13 bits of namespace to each, with the top
 * bit set for kernel object types, but it is easy to imagine other splits.
 * User and kernel software should be written so as to not place assumptions
 * about the specific values used here, as they may change.
 *
 * On Morello otype 0 is unsealed, and 1-3 are reserved.
 */
#define	CHERITEST_CHERI_OTYPE_BITS	(14)
#define	CHERITEST_CHERI_OTYPE_USER_MIN	(4)
#define	CHERITEST_CHERI_OTYPE_USER_MAX \
	((1 << (CHERITEST_CHERI_OTYPE_BITS - 1)) - 1)

#elif defined(__riscv)

#if defined(__riscv_zcheripurecap)
/*
 * Re-define these because RVY cheriintrin.h uses different names.
 * XXX-AM: Ideally we unify on a single naming convention.
 */
#define CHERI_PERM_STORE                CHERI_PERM_WRITE
#define CHERI_PERM_LOAD                 CHERI_PERM_READ
#define CHERI_PERM_GLOBAL               CHERI_PERM_CAPABILITY_LEVEL
#define CHERI_PERM_STORE_LOCAL_CAP      CHERI_PERM_STORE_LEVEL

/*
 * This file will be removed once Linux's asm/cheri.h contains
 * these definitions.
 */
#define CHERITEST_CHERI_PERM_SW_0 (1 << 6)
#define CHERITEST_CHERI_PERM_SW_1 (1 << 7)
#define CHERITEST_CHERI_PERM_SW_2 (1 << 8)
#define CHERITEST_CHERI_PERM_SW_3 (1 << 9)

#define CHERITEST_CHERI_PERMS_FIRST_RESERVED_BLOCK \
	(1 << 2 | 1 << 3 | 1 << 4)

#define CHERITEST_CHERI_PERMS_SECOND_RESERVED_BLOCK \
	(1 << 10 | 1 << 11  | 1 << 12 | 1 << 13 | 1 << 14 | 1 << 15)
#elif defined(__riscv_xcheri)
#define CHERI_PERM_WRITE CHERI_PERM_STORE
#define CHERI_PERM_READ CHERI_PERM_LOAD
#define CHERI_PERM_CAPABILITY_LEVEL CHERI_PERM_GLOBAL
#define CHERI_PERM_STORE_LEVEL CHERI_PERM_STORE_LOCAL_CAP
#define	CHERITEST_CHERI_PERM_SW_0 CHERI_PERM_SW0
#define	CHERITEST_CHERI_PERM_SW_1 CHERI_PERM_SW1
#define	CHERITEST_CHERI_PERM_SW_2 CHERI_PERM_SW2
#define	CHERITEST_CHERI_PERM_SW_3 CHERI_PERM_SW3

#define CHERITEST_CHERI_PERMS_FIRST_RESERVED_BLOCK 0
#define CHERITEST_CHERI_PERMS_SECOND_RESERVED_BLOCK 0

#define	CHERITEST_CHERI_OTYPE_BITS CHERI_OTYPE_BITS
#define	CHERITEST_CHERI_OTYPE_USER_MIN CHERI_OTYPE_USER_MIN
#define	CHERITEST_CHERI_OTYPE_USER_MAX CHERI_OTYPE_USER_MAX
#endif

#define CHERITEST_CHERI_PERMS_SWALL								\
	(CHERITEST_CHERI_PERM_SW_0 | CHERITEST_CHERI_PERM_SW_1 |	\
	CHERITEST_CHERI_PERM_SW_2 | CHERITEST_CHERI_PERM_SW_3)

#if defined(__riscv_xcheri)
/* Temporary: Reuse FreeBSD definitions for ISAv9 */
#define CHERITEST_CHERI_PERMS_USERSPACE_SEALCAP	CHERI_PERMS_USERSPACE_SEALCAP
#define CHERITEST_CHERI_CAP_USER_DATA_PERMS		CHERI_PERMS_USERSPACE_DATA
#else
#define CHERITEST_CHERI_CAP_USER_DATA_PERMS					\
	(CHERI_PERM_WRITE | CHERI_PERM_READ | CHERI_PERM_CAP |	\
	CHERI_PERM_LOAD_MUTABLE | CHERITEST_CHERI_PERMS_FIRST_RESERVED_BLOCK)
#endif
#define CHERITEST_CHERI_PERMS_USERSPACE_CODE	\
	(CHERI_PERM_EXECUTE | CHERI_PERM_READ)

#endif

/*
 * Root sealing capability for all userspace object capabilities.
 */
#define	CHERITEST_CHERI_SEALCAP_USERSPACE_PERMS	\
    CHERITEST_CHERI_PERMS_USERSPACE_SEALCAP
#define	CHERITEST_CHERI_SEALCAP_USERSPACE_BASE	\
    CHERITEST_CHERI_OTYPE_USER_MIN
#define	CHERITEST_CHERI_SEALCAP_USERSPACE_LENGTH	\
    (CHERITEST_CHERI_OTYPE_USER_MAX - CHERITEST_CHERI_OTYPE_USER_MIN + 1)
#define	CHERITEST_CHERI_SEALCAP_USERSPACE_OFFSET	0x0

/*
 * The software-defined permissions userspace capabilities are given. CheriBSD
 * reserves one for its syscall filter, which only code capabilities keep;
 * CHERI Linux does not, and does not define the macro.
 */
#ifdef CHERI_PERM_SYSCALL
#define	CHERITEST_CHERI_PERMS_SW_USERSPACE				\
	(CHERITEST_CHERI_PERMS_SWALL &					\
	    ~(CHERI_PERM_SW_VMEM | CHERI_PERM_SYSCALL))
#define	CHERITEST_CHERI_PERMS_SW_USERSPACE_CODE				\
	(CHERITEST_CHERI_PERMS_SW_USERSPACE | CHERI_PERM_SYSCALL)
#else
#define	CHERITEST_CHERI_PERMS_SW_USERSPACE				\
	(CHERITEST_CHERI_PERMS_SWALL & ~CHERI_PERM_SW_VMEM)
#define	CHERITEST_CHERI_PERMS_SW_USERSPACE_CODE				\
	CHERITEST_CHERI_PERMS_SW_USERSPACE
#endif

#endif /* !__SYS_CHERIREG_H__ */
