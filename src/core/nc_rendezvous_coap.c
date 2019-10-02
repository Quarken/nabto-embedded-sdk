#include "nc_rendezvous_coap.h"

#include <core/nc_coap_server.h>
#include <core/nc_packet.h>
#include <core/nc_iam.h>
#include <platform/np_logging.h>

#include <cbor.h>

#define LOG NABTO_LOG_MODULE_COAP

void nc_rendezvous_handle_coap_p2p_rendezvous(struct nabto_coap_server_request* request, void* data);

void nc_rendezvous_coap_init(struct nc_rendezvous_coap_context* context, struct nc_coap_server_context* coap, struct nc_rendezvous_context* rendezvous)
{
    context->coap = coap;
    context->rendezvous = rendezvous;
    nabto_coap_server_add_resource(nc_coap_server_get_server(coap), NABTO_COAP_CODE_POST,
                                   (const char*[]){"p2p", "rendezvous", NULL},
                                   &nc_rendezvous_handle_coap_p2p_rendezvous, context);
}
void nc_rendezvous_handle_coap_p2p_rendezvous(struct nabto_coap_server_request* request, void* data)
{
    struct nc_rendezvous_coap_context* ctx = (struct nc_rendezvous_coap_context*)data;

    uint8_t* payload;
    size_t payloadLength;
    struct nabto_coap_server_response* response = nabto_coap_server_create_response(request);
    nabto_coap_server_request_get_payload(request, (void**)&payload, &payloadLength);
    NABTO_LOG_BUF(LOG, payload, payloadLength);
    if (payload == NULL) {
        nabto_coap_server_response_set_code(response, (nabto_coap_code)NABTO_COAP_CODE(4,00));
        nabto_coap_server_response_ready(response);
        return;
    }

    struct nc_rendezvous_send_packet packet;
    packet.type = CT_RENDEZVOUS_DEVICE_REQUEST;
    nc_coap_server_context_request_get_connection_id(ctx->coap, request, packet.connectionId);

    CborParser parser;
    CborValue array;

    cbor_parser_init(payload, payloadLength, 0, &parser, &array);

    CborValue ep;
    cbor_value_enter_container(&array, &ep);

    while (cbor_value_is_map(&ep)) {

        CborValue ip;
        CborValue port;
        cbor_value_map_find_value(&ep, "Ip", &ip);
        cbor_value_map_find_value(&ep, "Port", &port);

        if (cbor_value_is_byte_string(&ip) &&
            cbor_value_is_unsigned_integer(&port))
        {

            uint64_t p;
            cbor_value_get_uint64(&port, &p);
            packet.ep.port = p;

            size_t ipLength;
            cbor_value_get_string_length(&ip, &ipLength);
            if (ipLength == 4) {
                packet.ep.ip.type = NABTO_IPV4;
                cbor_value_copy_byte_string(&ip, packet.ep.ip.ip.v4, &ipLength, NULL);
                nc_rendezvous_send_rendezvous(ctx->rendezvous, &packet);
            } else if (ipLength == 16) {
                packet.ep.ip.type = NABTO_IPV6;
                cbor_value_copy_byte_string(&ip, packet.ep.ip.ip.v6, &ipLength, NULL);
                nc_rendezvous_send_rendezvous(ctx->rendezvous, &packet);
            }
        }
        cbor_value_advance(&ep);
    }

    cbor_value_leave_container(&array, &ep);

    nabto_coap_server_response_set_code(response, (nabto_coap_code)NABTO_COAP_CODE(2,04));
    nabto_coap_server_response_ready(response);
}
