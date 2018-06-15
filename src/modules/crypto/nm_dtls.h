#ifndef NM_DTLS_H
#define NM_DTLS_H

#include <platform/np_platform.h>
#include <platform/np_crypto.h>

void nm_dtls_init(struct np_platform* pl);

np_error_code nm_dtls_async_connect(struct np_platform* pl, struct np_connection* conn,
                                    np_crypto_connect_callback cb, void* data);
np_error_code nm_dtls_async_send_to(struct np_platform* pl, np_crypto_context* ctx, uint8_t* buffer,
                                    uint16_t bufferSize, np_crypto_send_to_callback cb, void* data);
np_error_code nm_dtls_async_recv_from(struct np_platform* pl, np_crypto_context* ctx,
                                      enum application_data_type type, np_crypto_received_callback cb, void* data);
np_error_code nm_dtls_cancel_recv_from(struct np_platform* pl, np_crypto_context* ctx,
                                       enum application_data_type type);
np_error_code nm_dtls_async_close(struct np_platform* pl, np_crypto_context* ctx,
                                  np_crypto_close_callback cb, void* data);


#endif // NM_DTLS_H