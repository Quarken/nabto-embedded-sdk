#ifndef NM_DTLS_SRV_H
#define NM_DTLS_SRV_H

#include <platform/np_platform.h>
#include <platform/np_dtls_srv.h>

np_error_code nm_dtls_srv_init(struct np_platform* pl,
                  const unsigned char* publicKeyL, size_t publicKeySize,
                  const unsigned char* privateKeyL, size_t privateKeySize);

np_error_code nm_dtls_srv_create(struct np_platform* pl, np_connection* conn, np_dtls_srv_connection** dtls);
np_error_code nm_dtls_srv_async_send_to(struct np_platform* pl, np_dtls_srv_connection* ctx, uint8_t channelId,
                                        uint8_t* buffer, uint16_t bufferSize,
                                        np_dtls_srv_send_to_callback cb, void* data);
np_error_code nm_dtls_srv_async_recv_from(struct np_platform* pl, np_dtls_srv_connection* ctx,
                                          np_dtls_srv_received_callback cb, void* data);
np_error_code nm_dtls_srv_cancel_recv_from(struct np_platform* pl, np_dtls_srv_connection* ctx,
                                           enum application_data_type type);
np_error_code nm_dtls_srv_async_close(struct np_platform* pl, np_dtls_srv_connection* ctx,
                                      np_dtls_srv_close_callback cb, void* data);

#endif // NM_DTLS_SRV_H