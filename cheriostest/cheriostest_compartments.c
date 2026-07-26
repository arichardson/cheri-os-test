/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 John Baldwin
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency / Air Force Research Laboratory (DARPA/AFRL) Contract
 * No. FA8750-24-C-B047 ("DEC").
 */

#include <cheri/cheric.h>
#include "cheriostest.h"

static void
compartment_one_foo(void)
{
}

static void
compartment_two_foo(void)
{
}

static void
assert_disjoint_bounds(void *one, void *two, const char *label_one,
    const char *label_two)
{
	CHERIOSTEST_VERIFY2(
	    !cheritest_cheri_is_address_inbounds(one, cheri_base_get(two)) &&
	    !cheritest_cheri_is_address_inbounds(two, cheri_base_get(one)),
	    "%#p (%s) and %#p (%s) overlap", one, label_one, two, label_two);
}

CHERIOSTEST(compartment_pcc_bounds,
    "Check that PCC bounds of sub-object compartments are disjoint",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported"
#endif
)
{
#if defined(__linux__)
	cheriostest_failure_errx("Compartmentalisation is not supported by Linux");
#endif
	assert_disjoint_bounds(&compartment_one_foo, &compartment_two_foo,
	    "compartment_one_foo", "compartment_two_foo");
	assert_disjoint_bounds(&compartment_one_foo, &compartment_pcc_bounds,
	    "compartment_one_foo", "compartment_pcc_bounds");
	assert_disjoint_bounds(&compartment_two_foo, &compartment_pcc_bounds,
	    "compartment_two_foo", "compartment_pcc_bounds");
	cheriostest_success();
}
