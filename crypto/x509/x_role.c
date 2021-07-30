/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

/*-
 * Definition of RoleSyntax from RFC 5755 4.4.5
 *
 *
 * RoleSyntax ::= SEQUENCE {
 *      roleAuthority   [0] GeneralNames OPTIONAL,
 *      roleName        [1] GeneralName
 * }
 */

struct ROLE_SYNTAX_st {
    GENERAL_NAMES *roleAuthority;
    GENERAL_NAME *role;
};

ASN1_SEQUENCE(ROLE_SYNTAX) = {
    ASN1_IMP_SEQUENCE_OF_OPT(ROLE_SYNTAX, roleAuthority, GENERAL_NAME, 0),
    ASN1_EXP(ROLE_SYNTAX, role, GENERAL_NAME, 1),
} ASN1_SEQUENCE_END(ROLE_SYNTAX)

IMPLEMENT_ASN1_FUNCTIONS(ROLE_SYNTAX)

const GENERAL_NAMES *ROLE_SYNTAX_get0_rsAuthority(const ROLE_SYNTAX *rs)
{
    return rs->roleAuthority;
}

void ROLE_SYNTAX_set0_roleAuthority(ROLE_SYNTAX *rs, GENERAL_NAMES *names)
{
    GENERAL_NAMES_free(rs->roleAuthority);
    rs->roleAuthority = names;
}

GENERAL_NAME *ROLE_SYNTAX_get0_rs(ROLE_SYNTAX *rs)
{
    return rs->role;
}

int ROLE_SYNTAX_set1_role(ROLE_SYNTAX *rs, GENERAL_NAME *role)
{
    GENERAL_NAME *dup_val;

    if (role == NULL)
        return 0;

    if ((dup_val = GENERAL_NAME_dup(role)) == NULL)
        goto oom;

    GENERAL_NAME_free(rs->role);
    rs->role = dup_val;
    return 1;
oom:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
    return 0;
}

int ROLE_SYNTAX_print(BIO *bp, ROLE_SYNTAX *rs, int indent)
{
    int i;

    if (rs->roleAuthority != NULL) {
        for (i = 0; i < sk_GENERAL_NAME_num(rs->roleAuthority); i++) {
            if (BIO_printf(bp, "%*sAuthority: ", indent, "") <= 0)
                goto err;

            if (GENERAL_NAME_print(bp, sk_GENERAL_NAME_value(rs->roleAuthority,
                                                             i)) <= 0)
                goto err;

            if (BIO_printf(bp, "\n") <= 0)
                goto err;
        }
    }

    if (BIO_printf(bp, "%*s", indent, "") <= 0)
        goto err;

    if (GENERAL_NAME_print(bp, rs->role) <= 0)
        goto err;

    if (BIO_printf(bp, "\n") <= 0)
        goto err;

    return 1;

err:
    return 0;
}
