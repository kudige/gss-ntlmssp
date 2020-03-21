/*
   Copyright (C) 2013 Simo Sorce <simo@samba.org>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gssapi_ntlmssp.h"
#include "gss_ntlmssp.h"

const gss_OID_desc gssntlm_oid = {
    .length = GSS_NTLMSSP_OID_LENGTH,
    .elements = discard_const(GSS_NTLMSSP_OID_STRING)
};

#define oids ((gss_OID_desc *)const_oids)
static const gss_OID_desc const_oids[] = {
    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"},
    /* corresponding to an object-identifier value of
     * {iso(1) member-body(2) United States(840) mit(113554)
     * infosys(1) gssapi(2) generic(1) user_name(1)}.  The constant
     * GSS_C_NT_USER_NAME should be initialized to point
     * to that gss_OID_desc.
     */

    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02"},
    /* corresponding to an object-identifier value of
     * {iso(1) member-body(2) United States(840) mit(113554)
     * infosys(1) gssapi(2) generic(1) machine_uid_name(2)}.
     * The constant GSS_C_NT_MACHINE_UID_NAME should be
     * initialized to point to that gss_OID_desc.
     */

    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03"},
    /* corresponding to an object-identifier value of
     * {iso(1) member-body(2) United States(840) mit(113554)
     * infosys(1) gssapi(2) generic(1) string_uid_name(3)}.
     * The constant GSS_C_NT_STRING_UID_NAME should be
     * initialized to point to that gss_OID_desc.
     */

    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {6, (void *)"\x2b\x06\x01\x05\x06\x02"},
    /* corresponding to an object-identifier value of
     * {iso(1) org(3) dod(6) internet(1) security(5)
     * nametypes(6) gss-host-based-services(2)).  The constant
     * GSS_C_NT_HOSTBASED_SERVICE_X should be initialized to point
     * to that gss_OID_desc.  This is a deprecated OID value, and
     * implementations wishing to support hostbased-service names
     * should instead use the GSS_C_NT_HOSTBASED_SERVICE OID,
     * defined below, to identify such names;
     * GSS_C_NT_HOSTBASED_SERVICE_X should be accepted a synonym
     * for GSS_C_NT_HOSTBASED_SERVICE when presented as an input
     * parameter, but should not be emitted by GSS-API
     * implementations
     */

    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"},
    /* corresponding to an object-identifier value of
     * {iso(1) member-body(2) Unites States(840) mit(113554)
     * infosys(1) gssapi(2) generic(1) service_name(4)}.
     * The constant GSS_C_NT_HOSTBASED_SERVICE should be
     * initialized to point to that gss_OID_desc.
     */

    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {6, (void *)"\x2b\x06\01\x05\x06\x03"},
    /* corresponding to an object identifier value of
     * {1(iso), 3(org), 6(dod), 1(internet), 5(security),
     * 6(nametypes), 3(gss-anonymous-name)}.  The constant
     * and GSS_C_NT_ANONYMOUS should be initialized to point
     * to that gss_OID_desc.
     */

    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {6, (void *)"\x2b\x06\x01\x05\x06\x04"},
    /* corresponding to an object-identifier value of
     * {1(iso), 3(org), 6(dod), 1(internet), 5(security),
     * 6(nametypes), 4(gss-api-exported-name)}.  The constant
     * GSS_C_NT_EXPORT_NAME should be initialized to point
     * to that gss_OID_desc.
     */
    {6, (void *)"\x2b\x06\x01\x05\x06\x06"},
    /* corresponding to an object-identifier value of
     * {1(iso), 3(org), 6(dod), 1(internet), 5(security),
     * 6(nametypes), 6(gss-composite-export)}.  The constant
     * GSS_C_NT_COMPOSITE_EXPORT should be initialized to point
     * to that gss_OID_desc.
     */
    /* GSS_C_INQ_SSPI_SESSION_KEY 1.2.840.113554.1.2.2.5.5 */
    {11, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"},

    /* RFC 5587 attributes, see below */
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x01"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x02"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x03"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x04"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x05"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x06"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x07"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x08"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x09"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x0a"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x0b"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x0c"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x0d"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x0e"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x0f"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x10"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x11"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x12"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x13"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x14"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x15"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x16"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x17"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x18"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x19"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x1a"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x1b"},

    /*
     * GSS_SEC_CONTEXT_SASL_SSF_OID 1.2.840.113554.1.2.2.5.15
     * iso(1) member-body(2) United States(840) mit(113554)
     * infosys(1) gssapi(2) krb5(2) krb5-gssapi-ext(5) sasl-ssf(15)
     */
    {11, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0f"},
};

GSS_DLLIMP gss_OID GSS_C_NT_USER_NAME           = oids+0;
GSS_DLLIMP gss_OID gss_nt_user_name             = oids+0;

GSS_DLLIMP gss_OID GSS_C_NT_MACHINE_UID_NAME    = oids+1;
GSS_DLLIMP gss_OID gss_nt_machine_uid_name      = oids+1;

GSS_DLLIMP gss_OID GSS_C_NT_STRING_UID_NAME     = oids+2;
GSS_DLLIMP gss_OID gss_nt_string_uid_name       = oids+2;

GSS_DLLIMP gss_OID GSS_C_NT_HOSTBASED_SERVICE_X = oids+3;
gss_OID gss_nt_service_name_v2                  = oids+3;

GSS_DLLIMP gss_OID GSS_C_NT_HOSTBASED_SERVICE   = oids+4;
GSS_DLLIMP gss_OID gss_nt_service_name          = oids+4;

GSS_DLLIMP gss_OID GSS_C_NT_ANONYMOUS           = oids+5;

GSS_DLLIMP gss_OID GSS_C_NT_EXPORT_NAME         = oids+6;
gss_OID gss_nt_exported_name                    = oids+6;

GSS_DLLIMP gss_OID GSS_C_NT_COMPOSITE_EXPORT    = oids+7;

GSS_DLLIMP gss_OID GSS_C_INQ_SSPI_SESSION_KEY   = oids+8;

GSS_DLLIMP gss_const_OID GSS_C_MA_MECH_CONCRETE     = oids+9;
GSS_DLLIMP gss_const_OID GSS_C_MA_MECH_PSEUDO       = oids+10;
GSS_DLLIMP gss_const_OID GSS_C_MA_MECH_COMPOSITE    = oids+11;
GSS_DLLIMP gss_const_OID GSS_C_MA_MECH_NEGO         = oids+12;
GSS_DLLIMP gss_const_OID GSS_C_MA_MECH_GLUE         = oids+13;
GSS_DLLIMP gss_const_OID GSS_C_MA_NOT_MECH          = oids+14;
GSS_DLLIMP gss_const_OID GSS_C_MA_DEPRECATED        = oids+15;
GSS_DLLIMP gss_const_OID GSS_C_MA_NOT_DFLT_MECH     = oids+16;
GSS_DLLIMP gss_const_OID GSS_C_MA_ITOK_FRAMED       = oids+17;
GSS_DLLIMP gss_const_OID GSS_C_MA_AUTH_INIT         = oids+18;
GSS_DLLIMP gss_const_OID GSS_C_MA_AUTH_TARG         = oids+19;
GSS_DLLIMP gss_const_OID GSS_C_MA_AUTH_INIT_INIT    = oids+20;
GSS_DLLIMP gss_const_OID GSS_C_MA_AUTH_TARG_INIT    = oids+21;
GSS_DLLIMP gss_const_OID GSS_C_MA_AUTH_INIT_ANON    = oids+22;
GSS_DLLIMP gss_const_OID GSS_C_MA_AUTH_TARG_ANON    = oids+23;
GSS_DLLIMP gss_const_OID GSS_C_MA_DELEG_CRED        = oids+24;
GSS_DLLIMP gss_const_OID GSS_C_MA_INTEG_PROT        = oids+25;
GSS_DLLIMP gss_const_OID GSS_C_MA_CONF_PROT         = oids+26;
GSS_DLLIMP gss_const_OID GSS_C_MA_MIC               = oids+27;
GSS_DLLIMP gss_const_OID GSS_C_MA_WRAP              = oids+28;
GSS_DLLIMP gss_const_OID GSS_C_MA_PROT_READY        = oids+29;
GSS_DLLIMP gss_const_OID GSS_C_MA_REPLAY_DET        = oids+30;
GSS_DLLIMP gss_const_OID GSS_C_MA_OOS_DET           = oids+31;
GSS_DLLIMP gss_const_OID GSS_C_MA_CBINDINGS         = oids+32;
GSS_DLLIMP gss_const_OID GSS_C_MA_PFS               = oids+33;
GSS_DLLIMP gss_const_OID GSS_C_MA_COMPRESS          = oids+34;
GSS_DLLIMP gss_const_OID GSS_C_MA_CTX_TRANS         = oids+35;

GSS_DLLIMP gss_OID GSS_C_SEC_CONTEXT_SASL_SSF = oids+36;

#if 1
OM_uint32
generic_gss_create_empty_buffer_set(OM_uint32 * minor_status,
                                    gss_buffer_set_t *buffer_set)
{
    gss_buffer_set_t set;

    set = (gss_buffer_set_desc *) malloc(sizeof(*set));
    if (set == GSS_C_NO_BUFFER_SET) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    set->count = 0;
    set->elements = NULL;

    *buffer_set = set;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gss_add_buffer_set_member(OM_uint32 * minor_status,
                                  const gss_buffer_t member_buffer,
                                  gss_buffer_set_t *buffer_set)
{
    gss_buffer_set_t set;
    gss_buffer_t p;
    OM_uint32 ret;

    if (*buffer_set == GSS_C_NO_BUFFER_SET) {
        ret = generic_gss_create_empty_buffer_set(minor_status,
                                                  buffer_set);
        if (ret) {
            return ret;
        }
    }

    set = *buffer_set;
    set->elements = (gss_buffer_desc *)realloc(set->elements,
                                                        (set->count + 1) *
                                                        sizeof(gss_buffer_desc));
    if (set->elements == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    p = &set->elements[set->count];

    p->value = malloc(member_buffer->length);
    if (p->value == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    memcpy(p->value, member_buffer->value, member_buffer->length);
    p->length = member_buffer->length;

    set->count++;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gss_release_buffer(
    OM_uint32 *minor_status,
    gss_buffer_t buffer)
{
    if (minor_status)
        *minor_status = 0;

    /* if buffer is NULL, return */

    if (buffer == GSS_C_NO_BUFFER)
        return(GSS_S_COMPLETE);

    if (buffer->value) {
        free(buffer->value);
        buffer->length = 0;
        buffer->value = NULL;
    }

    return (GSS_S_COMPLETE);
}

OM_uint32
gss_release_buffer_set(OM_uint32 * minor_status,
                               gss_buffer_set_t *buffer_set)
{
    size_t i;
    OM_uint32 minor;

    *minor_status = 0;

    if (*buffer_set == GSS_C_NO_BUFFER_SET) {
        return GSS_S_COMPLETE;
    }

    for (i = 0; i < (*buffer_set)->count; i++) {
        gss_release_buffer(&minor, &((*buffer_set)->elements[i]));
    }

    if ((*buffer_set)->elements != NULL) {
        free((*buffer_set)->elements);
        (*buffer_set)->elements = NULL;
    }

    (*buffer_set)->count = 0;

    free(*buffer_set);
    *buffer_set = GSS_C_NO_BUFFER_SET;

    return GSS_S_COMPLETE;
}
#endif

#if 1
OM_uint32
gss_create_empty_oid_set(OM_uint32 *minor_status, gss_OID_set *oid_set)
{
    *minor_status = 0;

    if (oid_set == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    if ((*oid_set = (gss_OID_set) malloc(sizeof(gss_OID_set_desc)))) {
        memset(*oid_set, 0, sizeof(gss_OID_set_desc));
        return(GSS_S_COMPLETE);
    }
    else {
        *minor_status = ENOMEM;
        return(GSS_S_FAILURE);
    }
}

OM_uint32
gss_add_oid_set_member(OM_uint32 *minor_status,
                               gss_OID_desc * const member_oid,
                               gss_OID_set *oid_set)
{
    gss_OID     elist;
    gss_OID     lastel;

    *minor_status = 0;

    if (member_oid == NULL || member_oid->length == 0 ||
        member_oid->elements == NULL)
        return (GSS_S_CALL_INACCESSIBLE_READ);

    if (oid_set == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    elist = (*oid_set)->elements;
    /* Get an enlarged copy of the array */
    if (((*oid_set)->elements = (gss_OID) malloc(((*oid_set)->count+1) *
                                                          sizeof(gss_OID_desc)))) {
        /* Copy in the old junk */
        if (elist)
            memcpy((*oid_set)->elements,
                   elist,
                   ((*oid_set)->count * sizeof(gss_OID_desc)));

        /* Duplicate the input element */
        lastel = &(*oid_set)->elements[(*oid_set)->count];
        if ((lastel->elements =
             (void *) malloc((size_t) member_oid->length))) {
            /* Success - copy elements */
            memcpy(lastel->elements, member_oid->elements,
                   (size_t) member_oid->length);
            /* Set length */
            lastel->length = member_oid->length;

            /* Update count */
            (*oid_set)->count++;
            if (elist)
                free(elist);
            *minor_status = 0;
            return(GSS_S_COMPLETE);
        }
        else
            free((*oid_set)->elements);
    }
    /* Failure - restore old contents of list */
    (*oid_set)->elements = elist;
    *minor_status = ENOMEM;
    return(GSS_S_FAILURE);
}

#endif

#if 1

#define g_OID_equal(o1, o2)                                             \
        (((o1)->length == (o2)->length) &&                              \
        (memcmp((o1)->elements, (o2)->elements, (o1)->length) == 0))

int
gss_oid_equal(
    gss_const_OID first_oid,
    gss_const_OID second_oid)
{
    /* GSS_C_NO_OID doesn't match itself, per draft-josefsson-gss-capsulate. */
    if (first_oid == GSS_C_NO_OID || second_oid == GSS_C_NO_OID)
	return 0;
    return g_OID_equal(first_oid, second_oid);
}

OM_uint32
gss_release_oid_set(
    OM_uint32 *minor_status,
    gss_OID_set *set)
{
    size_t i;
    if (minor_status)
        *minor_status = 0;

    if (set == NULL)
        return(GSS_S_COMPLETE);

    if (*set == GSS_C_NULL_OID_SET)
        return(GSS_S_COMPLETE);

    for (i=0; i<(*set)->count; i++)
        free((*set)->elements[i].elements);

    free((*set)->elements);
    free(*set);

    *set = GSS_C_NULL_OID_SET;

    return(GSS_S_COMPLETE);
}
#endif

uint8_t gssntlm_required_security(int security_level, struct gssntlm_ctx *ctx)
{
    uint8_t resp;

    /* DC defaults */
    resp = SEC_DC_LM_OK | SEC_DC_NTLM_OK | SEC_DC_V2_OK;

    switch (security_level) {
    case 0:
        resp |= SEC_LM_OK | SEC_NTLM_OK;
        break;
    case 1:
        resp |= SEC_LM_OK | SEC_NTLM_OK | SEC_EXT_SEC_OK;
        break;
    case 2:
        resp |= SEC_NTLM_OK | SEC_EXT_SEC_OK;
        break;
    case 3:
        resp |= SEC_V2_ONLY | SEC_EXT_SEC_OK;
        break;
    case 4:
        resp |= SEC_NTLM_OK | SEC_EXT_SEC_OK;
        if (ctx->role == GSSNTLM_DOMAIN_CONTROLLER) resp &= ~SEC_DC_LM_OK;
        break;
    case 5:
        if (ctx->role == GSSNTLM_DOMAIN_CONTROLLER) resp = SEC_DC_V2_OK;
        resp |= SEC_V2_ONLY | SEC_EXT_SEC_OK;
        break;
    default:
        resp = 0xff;
        break;
    }

    return resp;
}

void gssntlm_set_role(struct gssntlm_ctx *ctx,
                      int desired, char *nb_domain_name)
{
    if (desired == GSSNTLM_CLIENT) {
        ctx->role = GSSNTLM_CLIENT;
    } else if (nb_domain_name && *nb_domain_name &&
               strcmp(nb_domain_name, DEF_NB_DOMAIN) != 0) {
        ctx->role = GSSNTLM_DOMAIN_SERVER;
    } else {
        ctx->role = GSSNTLM_SERVER;
    }
}

bool gssntlm_role_is_client(struct gssntlm_ctx *ctx)
{
    return (ctx->role == GSSNTLM_CLIENT);
}

bool gssntlm_role_is_server(struct gssntlm_ctx *ctx)
{
    switch (ctx->role) {
    case GSSNTLM_SERVER:
    case GSSNTLM_DOMAIN_SERVER:
    case GSSNTLM_DOMAIN_CONTROLLER:
        return true;
    default:
        break;
    }
    return false;
}

bool gssntlm_role_is_domain_member(struct gssntlm_ctx *ctx)
{
    switch (ctx->role) {
    case GSSNTLM_DOMAIN_SERVER:
    case GSSNTLM_DOMAIN_CONTROLLER:
        return true;
    default:
        break;
    }
    return false;
}

bool gssntlm_sec_lm_ok(struct gssntlm_ctx *ctx)
{
    switch (ctx->role) {
    case GSSNTLM_CLIENT:
    case GSSNTLM_SERVER:
        return (ctx->sec_req & SEC_LM_OK);
    case GSSNTLM_DOMAIN_SERVER:
        return true; /* defer decision to DC */
    case GSSNTLM_DOMAIN_CONTROLLER:
        return (ctx->sec_req & SEC_DC_LM_OK);
    }
    return false;
}

bool gssntlm_sec_ntlm_ok(struct gssntlm_ctx *ctx)
{
    switch (ctx->role) {
    case GSSNTLM_CLIENT:
    case GSSNTLM_SERVER:
        return (ctx->sec_req & SEC_NTLM_OK);
    case GSSNTLM_DOMAIN_SERVER:
        return true; /* defer decision to DC */
    case GSSNTLM_DOMAIN_CONTROLLER:
        return (ctx->sec_req & SEC_DC_NTLM_OK);
    }
    return false;
}

bool gssntlm_ext_sec_ok(struct gssntlm_ctx *ctx)
{
    return (ctx->sec_req & SEC_EXT_SEC_OK);
}

uint32_t gssntlm_context_is_valid(struct gssntlm_ctx *ctx, time_t *time_now)
{
    time_t now;

    if (!ctx) return GSS_S_NO_CONTEXT;
    if (!(ctx->int_flags & NTLMSSP_CTX_FLAG_ESTABLISHED)) {
        return GSS_S_NO_CONTEXT;
    }

    now = time(NULL);
    if (now > ctx->expiration_time) return GSS_S_CONTEXT_EXPIRED;

    if (time_now) *time_now = now;
    return GSS_S_COMPLETE;
}

int gssntlm_get_lm_compatibility_level(void)
{
    const char *envvar;

    envvar = getenv("LM_COMPAT_LEVEL");
    if (envvar != NULL) {
        return atoi(envvar);
    }

    /* use 3 by default for better compatibility */
    return 3;
}
