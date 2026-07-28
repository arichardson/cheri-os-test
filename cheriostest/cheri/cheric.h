/*-
 * Copyright (c) 2013-2016 Robert N. M. Watson
 * Copyright (c) 2021 Microsoft Corp.
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#ifndef	_CHERIC_H_
#define	_CHERIC_H_

#include <cheriintrin.h>
#include <stdbool.h>
#include <stddef.h>

/* Provide macros to make it easier to work with the raw CRAM/CRRL results: */
#define CHERITEST_CHERI_REPRESENTABLE_ALIGNMENT(len) \
	(~cheri_representable_alignment_mask(len) + 1)

#define CHERITEST_CHERI_ALIGN_MASK(l)	~(cheri_representable_alignment_mask(l))

#if defined(__linux__)
/* Check if the address is between cap.base and cap.top, i.e. in bounds */
static inline bool
cheri_is_address_inbounds(const void * __capability cap, ptraddr_t addr)
{
	return (addr >= cheri_base_get(cap) &&
		addr < (cheri_base_get(cap) + cheri_length_get(cap)));
}
#endif

#endif /* _SYS_CHERIC_H_ */
