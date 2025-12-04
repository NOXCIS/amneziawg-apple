// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

#ifndef WIREGUARDKITC_H
#define WIREGUARDKITC_H

#include <sys/types.h>
#include "key.h"
#include "x25519.h"

// Ensure key.h symbols are available through this umbrella header
_Static_assert(WG_KEY_LEN == 32, "WG_KEY_LEN must be 32");

// Ensure x25519.h symbols are available through this umbrella header
// Reference the function to satisfy linter (used by PrivateKey.swift)
// This macro exists solely to ensure the symbol is not optimized away by the linker
// when only Swift code references it through the module interface.
#define WIREGUARDKITC_X25519_REF (void *)curve25519_derive_public_key

/* From <sys/kern_control.h> */
/* Include system header if available, otherwise define structs ourselves */
#if __has_include(<sys/kern_control.h>)
#include <sys/kern_control.h>
/* Redefine CTLIOCGINFO so Swift can see it (Swift can't see macros from system headers) */
#undef CTLIOCGINFO
#endif
#define CTLIOCGINFO 0xc0644e03UL

#if !__has_include(<sys/kern_control.h>)
struct ctl_info {
    u_int32_t   ctl_id;
    char        ctl_name[96];
};
struct sockaddr_ctl {
    u_char      sc_len;
    u_char      sc_family;
    u_int16_t   ss_sysaddr;
    u_int32_t   sc_id;
    u_int32_t   sc_unit;
    u_int32_t   sc_reserved[5];
};
#endif

#endif /* WIREGUARDKITC_H */
