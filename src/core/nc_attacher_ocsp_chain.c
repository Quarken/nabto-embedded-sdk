#include "nc_attacher.h"
#include "nc_coap.h"

#include <platform/np_logging.h>

#include <cbor.h>

#define LOG NABTO_LOG_MODULE_ATTACHER

const char* ocspChainPath[] = {"ocsp", "chain"};

static void coap_attach_ocsp_chain_handler(struct nabto_coap_client_request* request, void* data);

np_error_code nc_attacher_ocsp_chain_request(struct nc_attach_context* ctx, nc_attacher_ocsp_chain_callback cb)
{
    if (ctx->ocspChainCallback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }

    struct nabto_coap_client_request* req;
    req = nabto_coap_client_request_new(nc_coap_client_get_client(ctx->coapClient),
                                        NABTO_COAP_METHOD_GET,
                                        2, ocspChainPath,
                                        &coap_attach_ocsp_chain_handler,
                                        ctx, ctx->dtls);
    if (req == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    ctx->ocspChainCallback = cb;

    nabto_coap_client_request_send(req);
    return NABTO_EC_OPERATION_STARTED;
}

bool coap_attach_ocsp_chain_handle_response(struct nc_attach_context* attacher, struct nabto_coap_client_request* request)
{
    struct nabto_coap_client_response* res = nabto_coap_client_request_get_response(request);
    if (!res) {
        return false;
    }

    uint16_t resCode = nabto_coap_client_response_get_code(res);
    if (!nc_coap_is_status_ok(resCode)) {
        return false;
    }

    uint16_t contentFormat;
    if (!nabto_coap_client_response_get_content_format(res, &contentFormat)) {
        return false;
    }

    if (contentFormat != (uint16_t)NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        return false;
    }

    const uint8_t* payload;
    size_t payloadSize;
    if (!nabto_coap_client_response_get_payload(res, &payload, &payloadSize)) {
        NABTO_LOG_ERROR(LOG, "No payload in CoAP response");
        return false;
    }

    CborParser parser;
    CborValue array;
    cbor_parser_init(payload, payloadSize, 0, &parser, &array);
    if (!cbor_value_is_array(&array)) {
        return false;
    }
    CborValue cborOcspResponse;
    cbor_value_enter_container(&array, &cborOcspResponse);
    size_t i = 0;
    while (!cbor_value_at_end(&cborOcspResponse)) {

        if (!cbor_value_is_byte_string(&cborOcspResponse)) {
            return false;
        }

        size_t length;
        if(cbor_value_get_string_length (&cborOcspResponse, &length) != CborNoError) {
            return false;
        }

        if (length > 4096) {
            return false;
        }

        uint8_t* ocspResponse = malloc(length);
        if (ocspResponse == NULL) {
            return false;
        }

        if (cbor_value_copy_byte_string(&cborOcspResponse, ocspResponse, &length, NULL) != CborNoError) {
            free(ocspResponse);
            return false;
        }

        struct np_platform* pl = attacher->pl;
        pl->dtlsC.handle_ocsp_response(attacher->dtls, i, ocspResponse, length);

        free(ocspResponse);
        i++;
        cbor_value_advance(&cborOcspResponse);
    }
    cbor_value_leave_container(&array, &cborOcspResponse);
    return true;
}

void coap_attach_ocsp_chain_handler(struct nabto_coap_client_request* request, void* data)
{
    struct nc_attach_context* attacher = data;
    coap_attach_ocsp_chain_handle_response(attacher, request);

    nabto_coap_client_request_free(request);

    nc_attacher_ocsp_chain_callback cb = attacher->ocspChainCallback;
    attacher->ocspChainCallback = NULL;

    cb(attacher);
}
