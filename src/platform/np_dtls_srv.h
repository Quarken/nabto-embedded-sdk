#ifndef NP_DTLS_SRV_H
#define NP_DTLS_SRV_H

#include <platform/np_error_code.h>
#include <platform/np_dtls.h>

typedef void (*np_dtls_srv_send_callback)(const np_error_code ec, void* data);
typedef void (*np_dtls_srv_mtu_callback)(const np_error_code ec, uint16_t mtu, void* data);
typedef void (*np_dtls_srv_sender)(bool activeChannel,
                                   np_communication_buffer* buffer, uint16_t bufferSize,
                                   np_dtls_srv_send_callback cb, void* data,
                                   void* senderData);

#include <core/nc_protocol_defines.h>

struct np_platform;

typedef struct np_dtls_srv_connection np_dtls_srv_connection;

np_error_code np_dtls_srv_init(struct np_platform* pl,
                               const unsigned char* publicKeyL, size_t publicKeySize,
                               const unsigned char* privateKeyL, size_t privateKeySize);

struct np_dtls_srv_module {

    np_error_code (*create)(struct np_platform* pl, struct np_dtls_srv_connection** dtls,
                            np_dtls_srv_sender sender, void* data);

    np_error_code (*async_send_to)(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                   uint8_t* buffer, uint16_t bufferSize,
                                   np_dtls_send_to_callback cb, void* data);

    np_error_code (*async_recv_from)(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                     np_dtls_received_callback cb, void* data);

    np_error_code (*cancel_recv_from)(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                      enum application_data_type type);

    np_error_code (*handle_packet)(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                   uint8_t channelId, np_communication_buffer* buffer, uint16_t bufferSize);

    np_error_code (*async_close)(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                 np_dtls_close_callback cb, void* data);

    np_error_code (*get_fingerprint)(struct np_platform* pl, struct np_dtls_srv_connection* ctx, uint8_t* fp);

    const char* (*get_alpn_protocol)(struct np_dtls_srv_connection* ctx);

    np_error_code (*get_packet_count)(struct np_dtls_srv_connection* ctx, uint32_t* recvCount, uint32_t* sentCount);

    np_error_code (*start_keep_alive)(struct np_dtls_srv_connection* ctx, uint32_t interval,
                                      uint8_t retryInterval, uint8_t maxRetries);
    np_error_code (*async_discover_mtu)(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                        np_dtls_srv_mtu_callback cb, void* data);
};

#endif // NP_DTLS_SRV_H
