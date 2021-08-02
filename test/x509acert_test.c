/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "testutil.h"

static const char *acert_file = NULL;

static int test_read_acert(void)
{
    X509_ACERT *acert = NULL;
    BIO *bp = NULL, *bout = NULL;
    int att_ind;
    int ret = 0;

    if (!TEST_ptr(bp = BIO_new_file(acert_file, "r")))
        goto err;

    if (!TEST_ptr(acert = PEM_read_bio_X509_ACERT(bp, NULL, NULL, NULL)))
        goto err;

    if (!TEST_ptr(bout = BIO_new_fp(stdout, BIO_NOCLOSE)))
        goto err;

    if (!TEST_int_gt(X509_ACERT_print(bout, acert), 0))
        goto err;

    /* Print the attributes that we know about if they exist */
    if ((att_ind = X509_ACERT_get_attr_by_NID(acert, NID_id_aca_group, -1)) >= 0) {
        ASN1_TYPE *at;
        IETF_ATTR_SYNTAX *ias;
        const unsigned char *data;
        X509_ATTRIBUTE *attr = X509_ACERT_get_attr(acert, att_ind);

        if (attr == NULL)
            goto err;

        if (BIO_puts(bout, "Group Attribute:\n") <= 0)
            goto err;

        at = X509_ATTRIBUTE_get0_type(attr, 0);
        data = at->value.sequence->data;
        ias = d2i_IETF_ATTR_SYNTAX(NULL, &data, at->value.sequence->length);

        if (ias == NULL)
            goto err;

        if (IETF_ATTR_SYNTAX_print(bout, ias, 8) <= 0) {
            IETF_ATTR_SYNTAX_free(ias);
            goto err;
        }

        IETF_ATTR_SYNTAX_free(ias);
    }

    if ((att_ind = X509_ACERT_get_attr_by_NID(acert, NID_role, -1)) >= 0) {
        ASN1_TYPE *at;
        ROLE_SYNTAX *rs;
        const unsigned char *data;
        X509_ATTRIBUTE *attr = X509_ACERT_get_attr(acert, att_ind);

        if (attr == NULL)
            goto err;

        if (BIO_puts(bout, "Role Attribute:\n") <= 0)
            goto err;

        at = X509_ATTRIBUTE_get0_type(attr, 0);
        data = at->value.sequence->data;
        rs = d2i_ROLE_SYNTAX(NULL, &data, at->value.sequence->length);

        if (rs == NULL)
            goto err;

        if (ROLE_SYNTAX_print(bout, rs, 8) <= 0) {
            ROLE_SYNTAX_free(rs);
            goto err;
        }

        ROLE_SYNTAX_free(rs);
    }

    ret = 1;
err:
    BIO_free(bp);
    BIO_free(bout);
    X509_ACERT_free(acert);
    ERR_print_errors_fp(stdout);
    return ret;
}

OPT_TEST_DECLARE_USAGE("acert_file\n")
int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(acert_file = test_get_argument(0)))
        return 0;

    ADD_TEST(test_read_acert);
    return 1;
}
