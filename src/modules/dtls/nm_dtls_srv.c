#include "nm_dtls_srv.h"
#include "nm_dtls_util.h"

#include <platform/np_logging.h>
#include <core/nc_version.h>
#include <core/nc_keep_alive.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
//#include <mbedtls/ssl_cookie.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/timing.h>

#include <string.h>
#include <stdlib.h>
#define NABTO_SSL_RECV_BUFFER_SIZE 4096

#define LOG NABTO_LOG_MODULE_DTLS_SRV
#define DEBUG_LEVEL 4

const char* nm_dtls_srv_alpnList[2];
char nm_dtls_srv_protocol[] = NABTO_PROTOCOL_VERSION;

enum sslState {
    CONNECTING,
    DATA,
    CLOSING
};

// TODO: consider joining the common elements of this and the np_dtls_cli_context into a common struct which is then used in this structure
struct np_dtls_srv_connection {
    struct np_connection* conn;
    enum sslState state;
    mbedtls_ssl_context ssl;
    struct nc_keep_alive_context keepAliveCtx;
    uint32_t recvCount;
    uint32_t sentCount;

    np_communication_buffer* sslRecvBuf;
    size_t sslRecvBufSize;
    np_communication_buffer* sslSendBuffer;
    size_t sslSendBufferSize;
    uint8_t recvBuffer[NABTO_SSL_RECV_BUFFER_SIZE];
    size_t recvBufferSize;
    uint8_t* sendBuffer;
    size_t sendBufferSize;

    uint8_t sendChannel;
    uint8_t currentChannelId;
    np_dtls_srv_received_callback appRecvCb;
    void* appRecvCbData;
    np_dtls_srv_received_callback kaRecvCb;
    void* kaRecvCbData;
    np_dtls_srv_send_to_callback sendCb;
    void* sendCbData;
    np_dtls_srv_close_callback closeCb;
    void* closeCbData;
    
    struct np_event sendEv;
    struct np_event recvEv;
    struct np_event closeEv;
    struct np_timed_event tEv;
    np_timestamp intermediateTp;
    np_timestamp finalTp;
};

struct nm_dtls_srv_context {
    struct np_platform* pl;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
//    mbedtls_ssl_cookie_ctx cookie_ctx;
    mbedtls_x509_crt publicKey;
    mbedtls_pk_context privateKey;
//    mbedtls_x509_crt cacert;
//    mbedtls_timing_delay_context timer;
//    mbedtls_pk_context pkey;
};

struct nm_dtls_srv_context server;
np_error_code nm_dtls_srv_init_config(const unsigned char* publicKeyL, size_t publicKeySize,
                                      const unsigned char* privateKeyL, size_t privateKeySize);
static void nm_dtls_srv_tls_logger( void *ctx, int level, const char *file, int line, const char *str );
void nm_dtls_srv_connection_send_callback(const np_error_code ec, void* data);
void nm_dtls_srv_do_one(void* data);

// Function called by mbedtls when data should be sent to the network
int nm_dtls_srv_mbedtls_send(void* ctx, const unsigned char* buffer, size_t bufferSize);
// Function called by mbedtls when it wants data from the network
int nm_dtls_srv_mbedtls_recv(void* ctx, unsigned char* buffer, size_t bufferSize);
// Function called by mbedtls which creates timeout events
void nm_dtls_srv_mbedtls_timing_set_delay(void* ctx, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds);
// Function called by mbedtls to determine when the next timeout event occurs
int nm_dtls_srv_mbedtls_timing_get_delay(void* ctx);
// callback function called by the connection module when data is ready from the network
void nm_dtls_srv_connection_received_callback(const np_error_code ec, struct np_connection* conn,
                                              uint8_t channelId,  np_communication_buffer* buffer,
                                              uint16_t bufferSize, void* data);

void nm_dtls_srv_event_send_to(void* data);

// Get the packet counters for given dtls_cli_context
np_error_code nm_dtls_srv_get_packet_count(np_dtls_srv_connection* ctx, uint32_t* recvCount, uint32_t* sentCount)
{
    *recvCount = ctx->recvCount;
    *sentCount = ctx->sentCount;
    return NABTO_EC_OK;
}

// Get the result of the application layer protocol negotiation
const char*  nm_dtls_srv_get_alpn_protocol(np_dtls_srv_connection* ctx) {
    return mbedtls_ssl_get_alpn_protocol(&ctx->ssl);
}


np_error_code nm_dtls_srv_init(struct np_platform* pl,
                               const unsigned char* publicKeyL, size_t publicKeySize,
                               const unsigned char* privateKeyL, size_t privateKeySize)
{
    pl->dtlsS.create = &nm_dtls_srv_create;
    pl->dtlsS.async_send_to = &nm_dtls_srv_async_send_to;
    pl->dtlsS.async_recv_from = &nm_dtls_srv_async_recv_from;
    pl->dtlsS.cancel_recv_from = &nm_dtls_srv_cancel_recv_from;
    pl->dtlsS.async_close = &nm_dtls_srv_async_close;
    pl->dtlsS.get_fingerprint = &nm_dtls_srv_get_fingerprint;
    pl->dtlsS.get_alpn_protocol = &nm_dtls_srv_get_alpn_protocol;
    pl->dtlsS.get_packet_count = &nm_dtls_srv_get_packet_count;
    server.pl = pl;
    nm_dtls_srv_alpnList[0] = nm_dtls_srv_protocol;
    nm_dtls_srv_alpnList[1] = NULL;
    
    return nm_dtls_srv_init_config(publicKeyL, publicKeySize, privateKeyL, privateKeySize);
}

/**
 * get peers fingerprint for given DTLS client context
 */
np_error_code nm_dtls_srv_get_fingerprint(struct np_platform* pl, np_dtls_srv_connection* ctx, uint8_t* fp)
{
    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ctx->ssl);
    if (!crt) {
        return NABTO_EC_FAILED;
    }
    return nm_dtls_util_fp_from_crt(crt, fp);
}

np_error_code nm_dtls_srv_create(struct np_platform* pl, np_connection* conn, np_dtls_srv_connection** dtls)
{
    int ret;
    *dtls = (np_dtls_srv_connection*)malloc(sizeof(np_dtls_srv_connection));
    if(!dtls) {
        return NABTO_EC_FAILED;
    }
    memset(*dtls, 0, sizeof(np_dtls_srv_connection));
    (*dtls)->conn = conn;
    (*dtls)->sslRecvBuf = server.pl->buf.allocate();
    (*dtls)->sslSendBuffer = server.pl->buf.allocate();

    NABTO_LOG_TRACE(LOG, "DTLS was allocated at: %u");

    //mbedtls connection initialization
    mbedtls_ssl_init( &((*dtls)->ssl) );
    if( ( ret = mbedtls_ssl_setup( &((*dtls)->ssl), &server.conf ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ssl_setup returned %d", ret );
        return NABTO_EC_FAILED;
    }

    mbedtls_ssl_set_timer_cb( &((*dtls)->ssl), (*dtls), &nm_dtls_srv_mbedtls_timing_set_delay,
                              &nm_dtls_srv_mbedtls_timing_get_delay );

    mbedtls_ssl_session_reset( &((*dtls)->ssl) );
    
//    ret = mbedtls_ssl_set_client_transport_id(&((*dtls)->ssl), (const unsigned char*)conn, sizeof(np_connection));
//    if (ret != 0) {
//        NABTO_LOG_ERROR(LOG, "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", -ret);
//        return NABTO_EC_FAILED;
//    }
    
    ret = mbedtls_ssl_set_hs_own_cert(&((*dtls)->ssl), &server.publicKey, &server.privateKey);
    if (ret != 0) {
        NABTO_LOG_ERROR(LOG, "failed ! mbedtls_ssl_set_hs_own_cert returned %d", ret);
        return NABTO_EC_FAILED;
    }

    mbedtls_ssl_set_bio( &((*dtls)->ssl), (*dtls),
                         &nm_dtls_srv_mbedtls_send, &nm_dtls_srv_mbedtls_recv, NULL );
    server.pl->conn.async_recv_from(server.pl, (*dtls)->conn, &nm_dtls_srv_connection_received_callback, (*dtls));

    return NABTO_EC_OK;
}

void nm_dtls_srv_ka_cb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(LOG,"DTLS SRV received keep alive callback with error code: %u", ec);
}


void nm_dtls_srv_do_one(void* data)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*)data;
    if (ctx->state == CONNECTING) {
        int ret;
        ctx->sendChannel = ctx->currentChannelId;
        ret = mbedtls_ssl_handshake( &ctx->ssl );
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // keep state as CONNECTING
            NABTO_LOG_TRACE(LOG, "Keeping CONNECTING state");
        } else if (ret == 0) {
            NABTO_LOG_INFO(LOG, "State changed to DATA");
            nc_keep_alive_init_srv(server.pl, &ctx->keepAliveCtx, ctx, &nm_dtls_srv_ka_cb, ctx);
            ctx->state = DATA;
        } else {
            NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_handshake returned -0x%04x", -ret );
            np_event_queue_cancel_timed_event(server.pl, &ctx->tEv);
            server.pl->conn.cancel_async_recv(server.pl, ctx->conn);
            free(ctx);
            return;
        }
    } else if (ctx->state == DATA) {
        int ret;
        ret = mbedtls_ssl_read(&ctx->ssl, server.pl->buf.start(ctx->sslRecvBuf), server.pl->buf.size(ctx->sslRecvBuf) );
        if (ret == 0) {
            // EOF
            ctx->state = CLOSING;
            NABTO_LOG_INFO(LOG, "Received EOF, state = CLOSING");
        } else if (ret > 0) {
            uint64_t seq = *((uint64_t*)ctx->ssl.in_ctr);
            uint8_t* ptr = server.pl->buf.start(ctx->sslRecvBuf);
            ctx->recvCount++;
            if (ptr[0] == AT_KEEP_ALIVE) {
                if (ptr[1] == CT_KEEP_ALIVE_REQUEST) {
                    NABTO_LOG_TRACE(LOG, "Keep alive request, responding imidiately");
                    ptr[1] = CT_KEEP_ALIVE_RESPONSE;
                    ctx->sendCb = NULL;
                    ctx->sendBuffer = ptr;
                    ctx->sendBufferSize = 16 + NABTO_PACKET_HEADER_SIZE;
                    nm_dtls_srv_event_send_to(ctx);
                    return;
                } else if (ctx->kaRecvCb) {
                    NABTO_LOG_TRACE(LOG, "found Callback function");
                    np_dtls_srv_received_callback cb = ctx->kaRecvCb;
                    ctx->kaRecvCb = NULL;
                    cb(NABTO_EC_OK, ctx->currentChannelId, seq, ctx->sslRecvBuf, ret, ctx->kaRecvCbData);
                }
            } else if (ctx->appRecvCb) {
                NABTO_LOG_TRACE(LOG, "found Callback function");
                np_dtls_srv_received_callback cb = ctx->appRecvCb;
                ctx->appRecvCb = NULL;
                cb(NABTO_EC_OK, ctx->currentChannelId, seq, ctx->sslRecvBuf, ret, ctx->appRecvCbData);
            } else {
                NABTO_LOG_TRACE(LOG, "received application packet with no callback");
            }
          
        } else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                   ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // OK
        } else {
            NABTO_LOG_ERROR(LOG, "Received ERROR: %i", ret);
            ctx->state = CLOSING;
            if(ctx->kaRecvCb != NULL) {
                ctx->kaRecvCb(NABTO_EC_CONNECTION_CLOSING, 0, 0, NULL, 0, ctx->kaRecvCbData);
            }
            if(ctx->appRecvCb != NULL) {
                ctx->appRecvCb(NABTO_EC_CONNECTION_CLOSING, 0, 0, NULL, 0, ctx->appRecvCbData);
            }
        }
    }

}

void nm_dtls_srv_event_send_to(void* data)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    int ret = mbedtls_ssl_write( &ctx->ssl, (unsigned char *) ctx->sendBuffer, ctx->sendBufferSize );
    if (ctx->sendCb == NULL) {
        ctx->sentCount++;
        return;
    }
    if (ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
        // packet too large
        ctx->sendCb(NABTO_EC_MALFORMED_PACKET, ctx->sendCbData);
    } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // should not be possible.
        ctx->sendCb(NABTO_EC_FAILED, ctx->sendCbData);
    } else if (ret < 0) {
        // unknown error
        ctx->sendCb(NABTO_EC_FAILED, ctx->sendCbData);
    } else {
        ctx->sentCount++;
        ctx->sendCb(NABTO_EC_OK, ctx->sendCbData);
    }
}

np_error_code nm_dtls_srv_async_send_to(struct np_platform* pl, np_dtls_srv_connection* ctx, uint8_t channelId,
                                        uint8_t* buffer, uint16_t bufferSize,
                                        np_dtls_srv_send_to_callback cb, void* data)
{
    ctx->sendCb = cb;
    ctx->sendCbData = data;
    ctx->sendBuffer = buffer;
    ctx->sendBufferSize = bufferSize;
    // If channel id is 0xff send on whatever channel is currently active
    if(channelId != 0xff) {
        ctx->sendChannel = channelId;
    }
    np_event_queue_post(server.pl, &ctx->sendEv, &nm_dtls_srv_event_send_to, ctx);

    return NABTO_EC_OK;
}

np_error_code nm_dtls_srv_async_recv_from(struct np_platform* pl, np_dtls_srv_connection* ctx,
                                          enum application_data_type type,
                                          np_dtls_srv_received_callback cb, void* data)
{
    if (ctx->state == CLOSING) {
        return NABTO_EC_CONNECTION_CLOSING;
    }
    if (type == AT_KEEP_ALIVE) {
        ctx->kaRecvCb = cb;
        ctx->kaRecvCbData = data;
    } else {
        ctx->appRecvCb = cb;
        ctx->appRecvCbData = data;
    }
    np_event_queue_post(server.pl, &ctx->recvEv, &nm_dtls_srv_do_one, ctx);
    return NABTO_EC_OK;
}

np_error_code nm_dtls_srv_cancel_recv_from(struct np_platform* pl, np_dtls_srv_connection* ctx,
                                           enum application_data_type type)
{
    if (type == AT_KEEP_ALIVE) {
        ctx->kaRecvCb = NULL;
    } else {
        ctx->appRecvCb = NULL;
    }
    return NABTO_EC_OK;
}

void nm_dtls_srv_event_close(void* data){
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    nc_keep_alive_stop(server.pl, &ctx->keepAliveCtx);
    mbedtls_ssl_close_notify(&ctx->ssl);
    mbedtls_ssl_free( &ctx->ssl );
    np_dtls_srv_close_callback cb = ctx->closeCb;
    void* cbData = ctx->closeCbData;
    server.pl->conn.cancel_async_recv(server.pl, ctx->conn);
    server.pl->conn.cancel_async_send(server.pl, ctx->conn);
    np_event_queue_cancel_timed_event(server.pl, &ctx->tEv);
    np_event_queue_cancel_event(server.pl, &ctx->sendEv);
    np_event_queue_cancel_event(server.pl, &ctx->recvEv);
    np_event_queue_cancel_event(server.pl, &ctx->closeEv);
    free(ctx);
    ctx = NULL;
    if(cb != NULL) {
        cb(NABTO_EC_OK, cbData);
    }
}

np_error_code nm_dtls_srv_async_close(struct np_platform* pl, np_dtls_srv_connection* ctx,
                                      np_dtls_srv_close_callback cb, void* data)
{
    ctx->closeCb = cb;
    ctx->closeCbData = data;
    ctx->state = CLOSING;
    np_event_queue_post(server.pl, &ctx->closeEv, &nm_dtls_srv_event_close, ctx);
    return NABTO_EC_OK;
}

void nm_dtls_srv_connection_received_callback(const np_error_code ec, struct np_connection* conn,
                                              uint8_t channelId, np_communication_buffer* buffer,
                                              uint16_t bufferSize, void* data)
{
    if ( data == NULL) {
        return;
    }
    NABTO_LOG_INFO(LOG, "connection data received callback");
    if (ec == NABTO_EC_OK) {
        np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
        ctx->currentChannelId = channelId;
        memcpy(ctx->recvBuffer, server.pl->buf.start(buffer), bufferSize);
        ctx->recvBufferSize = bufferSize;
        server.pl->conn.async_recv_from(server.pl, ctx->conn, &nm_dtls_srv_connection_received_callback, ctx);
        nm_dtls_srv_do_one(ctx);
    } else {
        NABTO_LOG_ERROR(LOG, "np_connection returned error code: %u", ec);
        nm_dtls_srv_event_close(data);
    }
}

np_error_code nm_dtls_srv_init_config(const unsigned char* publicKeyL, size_t publicKeySize,
                                      const unsigned char* privateKeyL, size_t privateKeySize)
{
    const char *pers = "dtls_server";
    int ret;
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
    mbedtls_ssl_config_init( &server.conf );
//    mbedtls_ssl_cookie_init( &server.cookie_ctx );
    mbedtls_entropy_init( &server.entropy );
    mbedtls_ctr_drbg_init( &server.ctr_drbg );
    mbedtls_x509_crt_init( &server.publicKey );
    mbedtls_pk_init( &server.privateKey );

    if( ( ret = mbedtls_ssl_config_defaults( &server.conf,
                                             MBEDTLS_SSL_IS_SERVER,
                                             MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ssl_config_defaults returned %i", ret);
        return NABTO_EC_FAILED;
    }

    mbedtls_ssl_conf_alpn_protocols(&server.conf, nm_dtls_srv_alpnList );

    if( ( ret = mbedtls_ctr_drbg_seed( &server.ctr_drbg, mbedtls_entropy_func, &server.entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ctr_drbg_seed returned %d", ret );
        return NABTO_EC_FAILED;
    }
    mbedtls_ssl_conf_dbg( &server.conf, nm_dtls_srv_tls_logger, stdout );
    mbedtls_ssl_conf_rng( &server.conf, mbedtls_ctr_drbg_random, &server.ctr_drbg );

//    ret = mbedtls_ssl_cookie_setup( &server.cookie_ctx, mbedtls_ctr_drbg_random, &server.ctr_drbg );
//    if( ret != 0)
//    {
//        NABTO_LOG_ERROR(LOG, "mbedtls_ssl_cookie_setup returned %d", ret );
//        return NABTO_EC_FAILED;
//    }

//    mbedtls_ssl_conf_dtls_cookies( &server.conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
//                                   &server.cookie_ctx );
    ret = mbedtls_x509_crt_parse( &server.publicKey, (const unsigned char*)publicKeyL, publicKeySize+1);
    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG, "mbedtls_x509_crt_parse returned %d ", ret);
        return NABTO_EC_FAILED;
    }

    NABTO_LOG_TRACE(LOG, "parsing privateKey: %s", privateKeyL);
    ret =  mbedtls_pk_parse_key( &server.privateKey, (const unsigned char*)privateKeyL, privateKeySize+1, NULL, 0 );
    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG,"mbedtls_pk_parse_key returned %d", ret);
        return NABTO_EC_FAILED;
    }
//    mbedtls_ssl_conf_ca_chain( &server.conf, server.publicKey.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &server.conf, &server.publicKey, &server.privateKey ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG,"mbedtls_ssl_conf_own_cert returned %d", ret);
        return NABTO_EC_FAILED;
    }
    return NABTO_EC_OK;
}
static void nm_dtls_srv_tls_logger( void *ctx, int level,
                                    const char *file, int line,
                                    const char *str )
{
    ((void) level);
    uint32_t severity;
    switch (level) {
        case 1:
            severity = NABTO_LOG_SEVERITY_ERROR;
            break;
        case 2:
            severity = NABTO_LOG_SEVERITY_INFO;
            break;
        default:
            severity = NABTO_LOG_SEVERITY_TRACE;
            break;
    }
    // TODO: fix this ugly hack to remove \n after all mbedtls log strings
    char ns[strlen(str)];
    memset(ns, 0, strlen(str));
    memcpy(ns, str, strlen(str));
    ns[strlen(str)-1] = '\0';
    NABTO_LOG_RAW(severity, LOG, line, file, ns );
}

// Function called by mbedtls when data should be sent to the network
int nm_dtls_srv_mbedtls_send(void* data, const unsigned char* buffer, size_t bufferSize)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    if (ctx->sslSendBufferSize == 0) {
        memcpy(server.pl->buf.start(ctx->sslSendBuffer), buffer, bufferSize);
        NABTO_LOG_TRACE(LOG, "mbedtls wants write:");
        NABTO_LOG_BUF(LOG, buffer, bufferSize);
        NABTO_LOG_TRACE(LOG, "ctx->sendChannel: %u, ctx->currentChannelId: %u", ctx->sendChannel, ctx->currentChannelId);
        ctx->sslSendBufferSize = bufferSize;
        if(ctx->sendChannel != ctx->currentChannelId) {
            server.pl->conn.async_send_to(server.pl, ctx->conn, ctx->sendChannel, ctx->sslSendBuffer, bufferSize, &nm_dtls_srv_connection_send_callback, ctx);
            ctx->sendChannel = ctx->currentChannelId;
        } else {
            server.pl->conn.async_send_to(server.pl, ctx->conn, ctx->currentChannelId, ctx->sslSendBuffer, bufferSize, &nm_dtls_srv_connection_send_callback, ctx);
        }
        return bufferSize;
    } else {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

}

void nm_dtls_srv_connection_send_callback(const np_error_code ec, void* data)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Connection Async Send failed with code: %u", ec);
        return;
    }
    if (data == NULL) {
        return;
    }
    ctx->sslSendBufferSize = 0;
    if(ctx->state == CLOSING) {
        return;
    }
    nm_dtls_srv_do_one(ctx);
}


// Function called by mbedtls when it wants data from the network
int nm_dtls_srv_mbedtls_recv(void* data, unsigned char* buffer, size_t bufferSize)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    if (ctx->recvBufferSize == 0) {
        NABTO_LOG_INFO(LOG, "Empty buffer, returning WANT_READ");
        return MBEDTLS_ERR_SSL_WANT_READ;
    } else {
        NABTO_LOG_TRACE(LOG, "mbtls wants read %u bytes into buffersize: %u", ctx->recvBufferSize, bufferSize);
        size_t maxCp = bufferSize > ctx->recvBufferSize ? ctx->recvBufferSize : bufferSize;
        memcpy(buffer, ctx->recvBuffer, maxCp);
        NABTO_LOG_INFO(LOG, "returning %i bytes to mbedtls:", maxCp);
//        NABTO_LOG_BUF(LOG, buffer, maxCp);
        ctx->recvBufferSize = 0;
        return maxCp;
    }
}

void nm_dtls_srv_timed_event_do_one(const np_error_code ec, void* data) {
    nm_dtls_srv_do_one(data);
}

// Function called by mbedtls which creates timeout events
void nm_dtls_srv_mbedtls_timing_set_delay(void* data, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    if (finalMilliseconds == 0) {
        // disable current timer  
        np_event_queue_cancel_timed_event(server.pl, &ctx->tEv);
        ctx->finalTp = 0;
    } else {
        server.pl->ts.set_future_timestamp(&ctx->intermediateTp, intermediateMilliseconds);
        server.pl->ts.set_future_timestamp(&ctx->finalTp, finalMilliseconds);
        np_event_queue_post_timed_event(server.pl, &ctx->tEv, finalMilliseconds, &nm_dtls_srv_timed_event_do_one, ctx);
    }
}

// Function called by mbedtls to determine when the next timeout event occurs
int nm_dtls_srv_mbedtls_timing_get_delay(void* data)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    if (ctx->finalTp) {
        if (server.pl->ts.passed_or_now(&ctx->finalTp)) {
            return 2;
        } else if (server.pl->ts.passed_or_now(&ctx->intermediateTp)) {
            return 1;
        } else {
            return 0;
        }
    } else {
        return -1;
    }
}
