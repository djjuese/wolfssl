
#include <stdlib.h>
#include <stdio.h>

/* Defining MPU_WRAPPERS_INCLUDED_FROM_API_FILE prevents task.h from redefining
all the API functions to use the MPU wrappers.  That should only be done when
task.h is included from an application file. */
#define MPU_WRAPPERS_INCLUDED_FROM_API_FILE

// #include <wolfssl/wolfcrypt/asn.h>
#include <ctype.h>

/* Some algorithms */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set USE_FAST_MATH there */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/integer.h>

#undef MPU_WRAPPERS_INCLUDED_FROM_API_FILE


#ifdef WOLFSSL_CUSTOM_CURVES
int EccKeyParamCopySize(char **dst, char *src, int Sz);
#endif

/* WOLFSSL_SUCCESS on ok */
void wolfSSL_BN_CTX_end(WOLFSSL_BN_CTX *ctx)
{
    wolfSSL_BN_CTX_free(ctx);
}

#ifdef WOLFSSL_CUSTOM_CURVES
int EccKeyParamCopySize(char **dst, char *src, int Sz)
{
    int ret = 0;
#ifdef WOLFSSL_ECC_CURVE_STATIC
    word32 length;
#endif

    if (dst == NULL || src == NULL)
        return BAD_FUNC_ARG;

#ifndef WOLFSSL_ECC_CURVE_STATIC
    if (*dst != NULL)
        XFREE(*dst, NULL, DYNAMIC_TYPE_ECC_BUFFER);
    *dst = src;
#else
    // length = (int)XSTRLEN(src) + 1;
    length = Sz;
    if (length > MAX_ECC_STRING)
    {
        WOLFSSL_MSG("ECC Param too large for buffer");
        ret = BUFFER_E;
    }
    else
    {
        XSTRNCPY(*dst, src, length);
    }
    XFREE(src, NULL, DYNAMIC_TYPE_ECC_BUFFER);
#endif

    return ret;
}
#endif /* WOLFSSL_CUSTOM_CURVES */

/* Calculate the value: generator * n + q[0] * m[0] + ... + q[num-1] * m[num-1]
 * return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_EC_POINTs_mul(const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *r,
                          const WOLFSSL_BIGNUM *n, size_t num,
                          const WOLFSSL_EC_POINT *p[], const WOLFSSL_BIGNUM *m[],
                          WOLFSSL_BN_CTX *ctx)
{
    int ret = WOLFSSL_FAILURE;
    size_t i = num;
    WOLFSSL_EC_POINT *tmp = NULL;

    (void)ctx;
    WOLFSSL_ENTER("wolfSSL_EC_POINTs_mul");

    /* num = 0 is not supported */
    if (num < 1)
        return ret;

    /*calc g*n + p[0]*m[0] first */
    ret = wolfSSL_EC_POINT_mul(group, r, n, p[0], m[0], ctx);
    if (num == 1)
        return ret;

    if (!(tmp = wolfSSL_EC_POINT_new(group)))
    {
        WOLFSSL_MSG("wolfSSL_EC_POINT_new error");
        return WOLFSSL_FAILURE;
    }

    for (i = 1; i < num; i++)
    {
        /* calc result = p[i] * m[i] */
        if (!(ret = wolfSSL_EC_POINT_mul(group, tmp, NULL, p[i], m[i], ctx)))
        {
            WOLFSSL_MSG("wolfSSL_EC_POINT_mul error");
            goto cleanup;
        }

        /*r = r + result*/
        if (!(ret = wolfSSL_EC_POINT_add(group, r, tmp, r, ctx)))
        {
            WOLFSSL_MSG("wolfSSL_EC_POINT_add error");
            goto cleanup;
        }
    }

    ret = WOLFSSL_SUCCESS;
cleanup:
    wolfSSL_EC_POINT_free(tmp);
    return ret;
}

/*
 * create customer curve
 */
WOLFSSL_EC_GROUP *wolfSSL_EC_GROUP_new_curve_GFp(const WOLFSSL_BIGNUM *p, const WOLFSSL_BIGNUM *a,
                                                 const WOLFSSL_BIGNUM *b, BN_CTX *ctx)
{
    WOLFSSL_EC_GROUP *g;
    int x, ret;
    int eccEnum, Sz1, Sz2, Sz3;
    char *sp = NULL;
    char *sa = NULL;
    char *sb = NULL;
    char *sName = NULL;
    ecc_set_type *curve;
    static const char customName[] = "Custom";

    (void)ctx;
    WOLFSSL_ENTER("wolfSSL_EC_GROUP_new_curve_GFp");

    /* specify custom curve ID */
    eccEnum = ECC_CURVE_CUSTOM;

    /* curve group */
    g = (WOLFSSL_EC_GROUP *)XMALLOC(sizeof(WOLFSSL_EC_GROUP), NULL,
                                    DYNAMIC_TYPE_ECC);
    if (g == NULL)
    {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_new_curve_GFp malloc failure");
        return NULL;
    }
    XMEMSET(g, 0, sizeof(WOLFSSL_EC_GROUP));

    /* set the nid of the curve */
    g->curve_nid = NID_undef;

    if (eccEnum != -1)
    {
        /* search and set the corresponding internal curve idx */
        for (x = 0; ecc_sets[x].size != 0; x++)
            if (ecc_sets[x].id == eccEnum)
            {
                g->curve_idx = x;
                g->curve_oid = ecc_sets[x].oidSum;
                break;
            }
    }

    /* initialize p/a/b for the custom curve */
    curve = &ecc_sets[x];

    sp = wolfSSL_BN_bn2hex(p);
    if (!sp)
        goto cleanup1;
    Sz1 = (int)XSTRLEN(sp) + 1;

    sa = wolfSSL_BN_bn2hex(a);
    if (!sa)
        goto cleanup2;
    Sz2 = (int)XSTRLEN(sa) + 1;

    sb = wolfSSL_BN_bn2hex(b);
    if (!sb)
        goto cleanup3;
    Sz3 = (int)XSTRLEN(sb) + 1;

    ret = EccKeyParamCopySize((char **)&curve->prime, sp, Sz1);
    if (ret == 0)
    {
        ret = EccKeyParamCopySize((char **)&curve->Af, sa, Sz2);
        if (ret == 0)
        {
            ret = EccKeyParamCopySize((char **)&curve->Bf, sb, Sz3);
        }
    }

    /* specify custom curve name */
    if (ret == 0)
    {
        sName = (char *)XMALLOC(sizeof(customName), NULL, DYNAMIC_TYPE_ECC);
        if (!sName)
        {
            goto cleanup1;
        }
        XSTRNCPY(sName, customName, sizeof(customName));
        ret = EccKeyParamCopySize((char **)&curve->name, sName, sizeof(customName));
    }

    /* can not be resigned because of const type for ecc_sets */
    if (ret == 0)
    {
        curve->size = (Sz1 - 1) / 2; // fixed 20210209
    }

    if (ret != 0)
        goto cleanup1;

    return g;

cleanup4:
    XFREE(sb, NULL, DYNAMIC_TYPE_ECC);
cleanup3:
    XFREE(sa, NULL, DYNAMIC_TYPE_ECC);
cleanup2:
    XFREE(sp, NULL, DYNAMIC_TYPE_ECC);
cleanup1:
    XFREE(g, NULL, DYNAMIC_TYPE_ECC);

    return NULL;
}

/*
 *  set generator / order/ cofactor
 *  Note: just only for 'custom curve'
 */
int wolfSSL_EC_GROUP_set_generator(WOLFSSL_EC_GROUP *group, const WOLFSSL_EC_POINT *generator,
                                   const WOLFSSL_BIGNUM *order, const WOLFSSL_BIGNUM *cofactor)
{
    char *sorder = NULL;
    char *scofactor = NULL;
    char *sGx = NULL;
    char *sGy = NULL;
    int x, ret, Sz1, Sz2, Sz3, Sz4;
    ecc_set_type *curve;

    if (!group || !generator || !order || !cofactor)
    {
        WOLFSSL_MSG("WOLFSSL_EC_GROUP_set_generator failure: error parameters");
        return WOLFSSL_FAILURE;
    }

    /* search the corresponding internal curve idx */
    for (x = 0; ecc_sets[x].size != 0; x++)
        if (ecc_sets[x].id == ECC_CURVE_CUSTOM)
        {
            if (group->curve_idx != x)
            {
                WOLFSSL_MSG("WOLFSSL_EC_GROUP_set_generator failure: EC group is not custom curve");
                return WOLFSSL_FAILURE;
            }
            break;
        }

    curve = &ecc_sets[x];

    sGx = wolfSSL_BN_bn2hex(generator->X);
    Sz1 = (int)XSTRLEN(sGx) + 1;

    sGy = wolfSSL_BN_bn2hex(generator->Y);
    if (!sGy)
        goto cleanup1;
    Sz2 = (int)XSTRLEN(sGy) + 1;

    sorder = wolfSSL_BN_bn2hex(order);
    if (!sorder)
        goto cleanup2;
    Sz3 = (int)XSTRLEN(sorder) + 1;

    scofactor = wolfSSL_BN_bn2hex(cofactor);
    if (!scofactor)
        goto cleanup3;
    Sz4 = (int)XSTRLEN(scofactor) + 1;

    ret = EccKeyParamCopySize((char **)&curve->Gx, sGx, Sz1);
    if (ret == 0)
    {
        ret = EccKeyParamCopySize((char **)&curve->Gy, sGy, Sz2);
        if (ret == 0)
        {
            ret = EccKeyParamCopySize((char **)&curve->order, sorder, Sz3);
            if (ret == 0)
            {
                // BE -> LE
                scofactor[3] = scofactor[0];
                scofactor[2] = scofactor[1];
                // curve->cofactor = (int)scofactor;
                curve->cofactor = 1;
                XFREE(scofactor, NULL, DYNAMIC_TYPE_ECC);
            }
        }
    }

    if (ret != 0)
        return WOLFSSL_FAILURE;

    return WOLFSSL_SUCCESS;

cleanup4:
    XFREE(scofactor, NULL, DYNAMIC_TYPE_ECC);
cleanup3:
    XFREE(sorder, NULL, DYNAMIC_TYPE_ECC);
cleanup2:
    XFREE(sGy, NULL, DYNAMIC_TYPE_ECC);
cleanup1:
    XFREE(sGx, NULL, DYNAMIC_TYPE_ECC);

    return WOLFSSL_FAILURE;
}