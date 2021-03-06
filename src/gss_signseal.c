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
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gssapi_ntlmssp.h"
#include "gss_ntlmssp.h"

uint32_t gssntlm_get_mic(uint32_t *minor_status,
                         gss_ctx_id_t context_handle,
                         gss_qop_t qop_req,
                         gss_buffer_t message_buffer,
                         gss_buffer_t message_token)
{
    struct gssntlm_ctx *ctx;
    struct ntlm_buffer message;
    struct ntlm_buffer signature;
    uint32_t retmaj, retmin;

    ctx = (struct gssntlm_ctx *)context_handle;
    retmaj = gssntlm_context_is_valid(ctx, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        return GSSERRS(ERR_BADCTX, retmaj);
    }
    if (qop_req != GSS_C_QOP_DEFAULT) {
        return GSSERRS(ERR_BADARG, GSS_S_BAD_QOP);
    }
    if (!message_buffer->value || message_buffer->length == 0) {
        return GSSERRS(ERR_BADARG, GSS_S_CALL_INACCESSIBLE_READ);
    }

    message_token->value = malloc(NTLM_SIGNATURE_SIZE);
    if (!message_token->value) {
        return GSSERRS(ENOMEM, GSS_S_FAILURE);
    }
    message_token->length = NTLM_SIGNATURE_SIZE;

    message.data = message_buffer->value;
    message.length = message_buffer->length;
    signature.data = message_token->value;
    signature.length = message_token->length;
    retmin = ntlm_sign(ctx->neg_flags, NTLM_SEND,
                       &ctx->crypto_state,
                       &message, &signature);
    if (retmin) {
        safefree(message_token->value);
        return GSSERRS(retmin, GSS_S_FAILURE);
    }

    return GSSERRS(0, GSS_S_COMPLETE);
}

uint32_t gssntlm_verify_mic(uint32_t *minor_status,
                            gss_ctx_id_t context_handle,
                            gss_buffer_t message_buffer,
                            gss_buffer_t message_token,
                            gss_qop_t *qop_state)
{
    struct gssntlm_ctx *ctx;
    struct ntlm_buffer message;
    uint8_t token[16];
    struct ntlm_buffer signature = { token, NTLM_SIGNATURE_SIZE };
    uint32_t retmaj, retmin;

    ctx = (struct gssntlm_ctx *)context_handle;
    retmaj = gssntlm_context_is_valid(ctx, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        return GSSERRS(ERR_BADCTX, retmaj);
    }
    if (!message_buffer->value || message_buffer->length == 0) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }
    if (qop_state) {
        *qop_state = GSS_C_QOP_DEFAULT;
    }

    message.data = message_buffer->value;
    message.length = message_buffer->length;
    retmin = ntlm_sign(ctx->neg_flags, NTLM_RECV,
                       &ctx->crypto_state,
                       &message, &signature);
    if (retmin) {
        return GSSERRS(retmin, GSS_S_FAILURE);
    }

    if (memcmp(signature.data,
               message_token->value, NTLM_SIGNATURE_SIZE) != 0) {
        return GSSERRS(0, GSS_S_BAD_SIG);
    }

    return GSSERRS(0, GSS_S_COMPLETE);
}

uint32_t gssntlm_get_session_key(uint32_t *minor_status,
                         gss_ctx_id_t context_handle,
                         gss_qop_t qop_req,
                         gss_buffer_t sessionkey)
{
    struct gssntlm_ctx *ctx;
    uint32_t retmaj, retmin;

    ctx = (struct gssntlm_ctx *)context_handle;
    retmaj = gssntlm_context_is_valid(ctx, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        return GSSERRS(ERR_BADCTX, retmaj);
    }
    if (qop_req != GSS_C_QOP_DEFAULT) {
        return GSSERRS(ERR_BADARG, GSS_S_BAD_QOP);
    }

    sessionkey->value = malloc(ctx->exported_session_key.length);
    if (!sessionkey->value) {
        return GSSERRS(ENOMEM, GSS_S_FAILURE);
    }
    sessionkey->length = ctx->exported_session_key.length;
    printf("*** sessionkey %p buf %p len %ld\n", sessionkey, sessionkey->value, sessionkey->length);

    memmove(sessionkey->value, ctx->exported_session_key.data, ctx->exported_session_key.length);
    
    return GSSERRS(0, GSS_S_COMPLETE);
}

uint32_t gssntlm_wrap(uint32_t *minor_status,
                      gss_ctx_id_t context_handle,
                      int conf_req_flag,
                      gss_qop_t qop_req,
                      gss_buffer_t input_message_buffer,
                      int *conf_state,
                      gss_buffer_t output_message_buffer)
{
    struct gssntlm_ctx *ctx;
    struct ntlm_buffer message;
    struct ntlm_buffer output;
    struct ntlm_buffer signature;
    uint32_t retmaj, retmin;

    ctx = (struct gssntlm_ctx *)context_handle;
    retmaj = gssntlm_context_is_valid(ctx, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        return GSSERRS(ERR_BADCTX, retmaj);
    }
    if (qop_req != GSS_C_QOP_DEFAULT) {
        return GSSERRS(ERR_BADARG, GSS_S_BAD_QOP);
    }
    if (!input_message_buffer->value || input_message_buffer->length == 0) {
        return GSSERRS(ERR_BADARG, GSS_S_CALL_INACCESSIBLE_READ);
    }
    if (conf_state) {
        *conf_state = 0;
    }

    if (conf_req_flag == 0) {
        /* ignore, always seal */
    }

    output_message_buffer->length =
        input_message_buffer->length + NTLM_SIGNATURE_SIZE;
    output_message_buffer->value = malloc(output_message_buffer->length);
    if (!output_message_buffer->value) {
        return GSSERRS(ENOMEM, GSS_S_FAILURE);
    }

    message.data = input_message_buffer->value;
    message.length = input_message_buffer->length;
    signature.data = output_message_buffer->value;
    signature.length = NTLM_SIGNATURE_SIZE;
    output.data = (uint8_t *)output_message_buffer->value + NTLM_SIGNATURE_SIZE;
    output.length = input_message_buffer->length;
    retmin = ntlm_seal(ctx->neg_flags, &ctx->crypto_state,
                       &message, &output, &signature);
    if (retmin) {
        safefree(output_message_buffer->value);
        return GSSERRS(retmin, GSS_S_FAILURE);
    }

    return GSSERRS(0, GSS_S_COMPLETE);
}

uint32_t gssntlm_unwrap(uint32_t *minor_status,
                        gss_ctx_id_t context_handle,
                        gss_buffer_t input_message_buffer,
                        gss_buffer_t output_message_buffer,
                        int *conf_state,
                        gss_qop_t *qop_state)
{
    struct gssntlm_ctx *ctx;
    struct ntlm_buffer message;
    struct ntlm_buffer output;
    uint8_t sig[16];
    struct ntlm_buffer signature = { sig, NTLM_SIGNATURE_SIZE };
    uint32_t retmaj, retmin;

    ctx = (struct gssntlm_ctx *)context_handle;
    retmaj = gssntlm_context_is_valid(ctx, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        return GSSERRS(ERR_BADCTX, retmaj);
    }
    if (!input_message_buffer->value || input_message_buffer->length == 0) {
        return GSSERRS(ERR_BADARG, GSS_S_CALL_INACCESSIBLE_READ);
    }
    if (conf_state) {
        *conf_state = 0;
    }
    if (qop_state) {
        *qop_state = GSS_C_QOP_DEFAULT;
    }

    output_message_buffer->length =
        input_message_buffer->length - NTLM_SIGNATURE_SIZE;
    output_message_buffer->value = malloc(output_message_buffer->length);
    if (!output_message_buffer->value) {
        return GSSERRS(ENOMEM, GSS_S_FAILURE);
    }

    message.data = (uint8_t *)input_message_buffer->value + NTLM_SIGNATURE_SIZE;
    message.length = input_message_buffer->length - NTLM_SIGNATURE_SIZE;
    output.data = output_message_buffer->value;
    output.length = output_message_buffer->length;
    retmin = ntlm_unseal(ctx->neg_flags, &ctx->crypto_state,
                         &message, &output, &signature);
    if (retmin) {
        safefree(output_message_buffer->value);
        return GSSERRS(retmin, GSS_S_FAILURE);
    }

    if (memcmp(input_message_buffer->value,
               signature.data, NTLM_SIGNATURE_SIZE) != 0) {
        safefree(output_message_buffer->value);
        return GSSERRS(0, GSS_S_BAD_SIG);
    }

    return GSSERRS(0, GSS_S_COMPLETE);
}

uint32_t gssntlm_wrap_size_limit(uint32_t *minor_status,
                                 gss_ctx_id_t context_handle,
                                 int conf_req_flag,
                                 gss_qop_t qop_req,
                                 uint32_t req_output_size,
                                 uint32_t *max_input_size)
{
    struct gssntlm_ctx *ctx;
    uint32_t retmaj, retmin;

    ctx = (struct gssntlm_ctx *)context_handle;
    retmaj = gssntlm_context_is_valid(ctx, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        return GSSERRS(ERR_BADCTX, retmaj);
    }

    if (qop_req != GSS_C_QOP_DEFAULT) {
        return GSSERRS(ERR_BADARG, GSS_S_BAD_QOP);
    }

    if (req_output_size < 16) {
        *max_input_size = 0;
    } else {
        *max_input_size = req_output_size - NTLM_SIGNATURE_SIZE;
    }

    return GSSERRS(0, GSS_S_COMPLETE);
}
