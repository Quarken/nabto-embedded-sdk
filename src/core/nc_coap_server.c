#include "nc_coap_server.h"

#include <platform/np_logging.h>
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_COAP

void nc_coap_server_set_infinite_stamp(struct nc_coap_server_context* ctx);
void nc_coap_server_event(struct nc_coap_server_context* ctx);
uint32_t nc_coap_server_get_stamp(void* userData);
void nc_coap_server_notify_event(void* userData);
void nc_coap_server_handle_send(struct nc_coap_server_context* ctx);
void nc_coap_server_handle_wait(struct nc_coap_server_context* ctx);
void nc_coap_server_send_to_callback(const np_error_code ec, void* data);
void nc_coap_server_handle_timeout(const np_error_code ec, void* data);

// TODO: Dummy function since this is not yet used
void nc_coap_server_event_handler(void* hest, enum nabto_coap_server_event event, ...)
{
    
}

void nc_coap_server_init(struct np_platform* pl, struct nc_coap_server_context* ctx)
{
    ctx->pl = pl;
    ctx->sendBuffer = pl->buf.allocate();
    ctx->isSending = false;
    nabto_coap_server_init(&ctx->server, &nc_coap_server_get_stamp, &nc_coap_server_notify_event, &nc_coap_server_event_handler, ctx);
    nc_coap_server_set_infinite_stamp(ctx);
}

void nc_coap_server_handle_packet(struct nc_coap_server_context* ctx, struct nc_client_connection* conn,
                                  np_communication_buffer* buffer, uint16_t bufferSize)
{
    nabto_coap_server_handle_packet(&ctx->server,(nabto_coap_server_connection*) nc_client_connect_get_dtls_connection(conn), ctx->pl->buf.start(buffer), bufferSize);
    nc_coap_server_event(ctx);
}

void nc_coap_server_event(struct nc_coap_server_context* ctx)
{
    enum nabto_coap_server_next_event nextEvent = nabto_coap_server_next_event(&ctx->server);
    NABTO_LOG_TRACE(LOG, "nc_coap_server_event: %u", nextEvent); 
    switch (nextEvent) {
        case NABTO_COAP_SERVER_NEXT_EVENT_SEND:
            nc_coap_server_handle_send(ctx);
            return;
        case NABTO_COAP_SERVER_NEXT_EVENT_WAIT:
            nc_coap_server_handle_wait(ctx);
            return;
        case NABTO_COAP_SERVER_NEXT_EVENT_NOTHING:
            return;
    }
    //nc_coap_server_event(ctx);
}

struct nc_coap_server_send_ctx {
    struct np_dtls_srv_send_context dtls;
    struct nc_coap_server_context* ctx;
};

void nc_coap_server_handle_send(struct nc_coap_server_context* ctx)
{
    NABTO_LOG_TRACE(LOG, "handle send");
    if (ctx->isSending) {
        return;
    }

    nabto_coap_server_connection* connection = nabto_coap_server_get_connection_send(&ctx->server);
    if (!connection) {
        nc_coap_server_event(ctx);
        return;
    }
    np_dtls_srv_connection* dtls = (np_dtls_srv_connection*)connection;

    // TODO: Using 1400 as it is assumed to fit with the network MTU use mtu discovery result
    size_t bufferSize = 1400;
    if (ctx->pl->buf.size(ctx->sendBuffer) < bufferSize) {
        bufferSize = ctx->pl->buf.size(ctx->sendBuffer);
    }

    // TODO: don't use malloc use new buffer manager
    struct nc_coap_server_send_ctx* sendCtx = malloc(sizeof(struct nc_coap_server_send_ctx));
    sendCtx->dtls.buffer = (uint8_t*)malloc(1500);
    uint8_t* sendEnd = nabto_coap_server_handle_send(&ctx->server, sendCtx->dtls.buffer, sendCtx->dtls.buffer+bufferSize);

    if (sendEnd == NULL || sendEnd < sendCtx->dtls.buffer) {
        free(sendCtx->dtls.buffer);
        free(sendCtx);
        nc_coap_server_event(ctx);
        return;
    }
    
//    sendCtx->dtls.buffer = ctx->pl->buf.start(ctx->sendBuffer);
    sendCtx->dtls.bufferSize = sendEnd - sendCtx->dtls.buffer;
    sendCtx->dtls.cb = &nc_coap_server_send_to_callback;
    sendCtx->dtls.data = sendCtx;
    sendCtx->ctx = ctx;
    ctx->isSending = true;
    ctx->pl->dtlsS.async_send_to(ctx->pl, dtls, &sendCtx->dtls);
}

void nc_coap_server_handle_wait(struct nc_coap_server_context* ctx)
{
    NABTO_LOG_TRACE(LOG, "handle wait");
    uint32_t nextStamp;
    nabto_coap_server_get_next_timeout(&ctx->server, &nextStamp);
    if (nabto_coap_is_stamp_less(nextStamp, ctx->currentExpiry)) {
        ctx->currentExpiry = nextStamp;
        uint32_t now = nabto_coap_server_stamp_now(&ctx->server);
        int32_t diff = nabto_coap_stamp_diff(nextStamp, now);
        if (diff < 0) {
            diff = 0;
        }
        np_event_queue_post_timed_event(ctx->pl, &ctx->timer, diff, &nc_coap_server_handle_timeout, ctx);
    }
}

void nc_coap_server_handle_timeout(const np_error_code ec, void* data)
{
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*) data;
    NABTO_LOG_TRACE(LOG, "Handle timeout called");
    nc_coap_server_set_infinite_stamp(ctx);
    nabto_coap_server_handle_timeout(&ctx->server);
    nc_coap_server_event(ctx);
}

struct nabto_coap_server* nc_coap_server_get_server(struct nc_coap_server_context* ctx)
{
    return &ctx->server;
}

// ========= UTIL FUNCTIONS ============= //
void nc_coap_server_send_to_callback(const np_error_code ec, void* data)
{
    struct nc_coap_server_send_ctx* sendCtx = (struct nc_coap_server_send_ctx*)data;
//    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*)data;
    NABTO_LOG_TRACE(LOG, "coap_server_send_to_callback");
    sendCtx->ctx->isSending = false;
    nc_coap_server_event(sendCtx->ctx);
    free(sendCtx->dtls.buffer);
    free(sendCtx);
}

uint32_t nc_coap_server_get_stamp(void* userData) {
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*)userData;
    return ctx->pl->ts.now_ms();
}

void nc_coap_server_notify_event_callback(void* userData)
{
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*)userData;
    nc_coap_server_event(ctx);
}

void nc_coap_server_notify_event(void* userData)
{
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*)userData;
    NABTO_LOG_TRACE(LOG, "nc_coap_server_notify_event received");
    np_event_queue_post(ctx->pl, &ctx->ev, &nc_coap_server_notify_event_callback, ctx);
}

void nc_coap_server_set_infinite_stamp(struct nc_coap_server_context* ctx)
{
    ctx->currentExpiry = nabto_coap_server_stamp_now(&ctx->server);
    ctx->currentExpiry += (1 << 29);
}