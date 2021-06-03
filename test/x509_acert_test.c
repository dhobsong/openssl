/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/pem.h>
#include <openssl/x509_acert.h>

#include "testutil.h"

X509_ACERT *orig_acert;
EVP_PKEY *privkey;

static int print_acert(X509_ACERT *acert)
{
    BIO *bout;
    int ret;

    if (!TEST_ptr(bout = BIO_new_fp(stdout, BIO_NOCLOSE)))
    return 0;

    ret = TEST_int_eq(X509_ACERT_print(bout, orig_acert), 1);

    BIO_free(bout);
    return ret;
}

static int test_print_acert(void)
{
    int ret = 0;

    if (!TEST_int_eq(print_acert(orig_acert), 1))
        goto err;

    ret = 1;
err:
    ERR_print_errors_fp(stderr);
    return ret;
}

static int test_object_group_attr(void)
{
    X509_ACERT *acert = X509_ACERT_dup(orig_acert);
    int i, ret = 0;
    BIO *bout;

    if (!TEST_ptr(acert))
        return 0;

    if (!TEST_ptr(bout = BIO_new_fp(stdout, BIO_NOCLOSE)))
        goto done;

    for (i = 0; i < X509_ACERT_get_attr_count(acert); i++) {
        X509_ATTRIBUTE *attr = X509_ACERT_get_attr(acert, i);
        ASN1_OBJECT *obj = X509_ATTRIBUTE_get0_object(attr);
        int acnt, j;

        if (OBJ_cmp(obj, OBJ_txt2obj("id-aca-group", 0)))
            continue;

        acnt = X509_ATTRIBUTE_count(attr);

        for (j = 0; j < acnt; j++) {
            OSSL_IETF_ATTR_SYNTAX *ias;
            ASN1_TYPE *type = X509_ATTRIBUTE_get0_type(attr, j);
            const unsigned char *p;

            if (!TEST_int_eq(type->type,V_ASN1_SEQUENCE))
                goto done;

            p = type->value.sequence->data;

            ias = d2i_OSSL_IETF_ATTR_SYNTAX(NULL, &p,
                                            type->value.sequence->length);

            if (!TEST_ptr(ias))
                goto done;

            if (!TEST_int_eq(OSSL_IETF_ATTR_SYNTAX_print(bout, ias, 4), 1)) {
                OSSL_IETF_ATTR_SYNTAX_free(ias);
                goto done;
            }

            OSSL_IETF_ATTR_SYNTAX_free(ias);
	    ret = 1;
	    goto done;
        }
    }

    TEST_error("id-ac-group attribute not found\n");

done:
    X509_ACERT_free(acert);
    BIO_free(bout);
    return ret;
}

static int test_acert_sign(void)
{
    int ret = 0;
    X509_ACERT *acert = X509_ACERT_dup(orig_acert);

    if (!TEST_ptr(acert))
	    return 0;

    if (!TEST_int_gt(X509_ACERT_sign(acert, privkey, EVP_sha256()), 0) ||
        !TEST_int_eq(X509_ACERT_verify(acert, privkey), 1))
        goto err;

    ret = 1;

err:
    X509_ACERT_free(acert);
    return ret;
}

OPT_TEST_DECLARE_USAGE("acert_file signing_key\n")
int setup_tests(void)
{
    const char *acert_file = NULL;
    const char *key_file = NULL;
    BIO *bp;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(acert_file = test_get_argument(0)))
        return 0;

    if (!TEST_ptr(key_file = test_get_argument(1)))
        return 0;

    if (!TEST_ptr(bp = BIO_new_file(acert_file, "r")))
        return 0;

    if (!TEST_ptr(orig_acert = PEM_read_bio_X509_ACERT(bp, NULL, NULL, NULL))) {
        BIO_free(bp);
        return 0;
    }

    if (!TEST_ptr(bp = BIO_new_file(key_file, "r")))
        return 0;

    if (!TEST_ptr(privkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL))) {
        BIO_free(bp);
        return 0;
    }
    BIO_free(bp);

    ADD_TEST(test_print_acert);
    ADD_TEST(test_object_group_attr);
    ADD_TEST(test_acert_sign);

    return 1;
}

void cleanup_tests(void)
{
    X509_ACERT_free(orig_acert);
    EVP_PKEY_free(privkey);
}
