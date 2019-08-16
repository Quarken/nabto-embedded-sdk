#ifndef NC_KEEP_ALIVE_H
#define NC_KEEP_ALIVE_H

#include <platform/np_platform.h>
#include <platform/np_dtls_srv.h>

#include <nabto_types.h>

#ifndef NC_KEEP_ALIVE_MTU_MAX
#define NC_KEEP_ALIVE_MTU_MAX 1400
#endif

#ifndef NC_KEEP_ALIVE_MTU_START
#define NC_KEEP_ALIVE_MTU_START 1024
#endif

#ifndef NC_KEEP_ALIVE_MTU_RETRY_INTERVAL
#define NC_KEEP_ALIVE_MTU_RETRY_INTERVAL 2000 // ms
#endif

#ifndef NC_KEEP_ALIVE_MTU_MAX_TRIES
#define NC_KEEP_ALIVE_MTU_MAX_TRIES 5
#endif

struct nc_keep_alive_context
{
    struct np_platform* pl;
    uint16_t kaInterval;
    uint8_t kaRetryInterval;
    uint8_t kaMaxRetries;
    uint32_t lastRecvCount;
    uint32_t lastSentCount;
    uint8_t lostKeepAlives;
    uint16_t n;

    bool isSending;
    uint8_t sendBuffer[18];
    struct np_timed_event keepAliveEvent;

};

enum nc_keep_alive_action{
    DO_NOTHING,
    SEND_KA,
    KA_TIMEOUT,
    DTLS_ERROR
};

typedef void (*keep_alive_wait_callback)(const np_error_code ec, void* data);

/**
 * Init keep alive with the given parameters
 * @param pl            The platform to use
 * @param ctx           The keep alive context to use for keep alive
 * @param interval      The interval between keep alive transmissions
 * @param retryInterval The interval between retransmissions in case of packet loss
 * @param maxRetries    The maximum amount of retransmissions before a connection is considered dead
 */
void nc_keep_alive_init(struct nc_keep_alive_context* ctx, struct np_platform* pl, uint32_t interval, uint8_t retryInterval, uint8_t maxRetries);

void nc_keep_alive_deinit(struct nc_keep_alive_context* ctx);

enum nc_keep_alive_action nc_keep_alive_should_send(struct nc_keep_alive_context* ctx, uint32_t recvCount, uint32_t sentCount);


void nc_keep_alive_wait(struct nc_keep_alive_context* ctx, keep_alive_wait_callback cb, void* data);
void nc_keep_alive_packet_sent(const np_error_code ec, void* data);

/**
 * Sets keep alive settings for a given context.
 * @param kaInterval      set the interval between successfull keep alive
 * @param kaRetryInterval set the interval between retransmissions for packet losses
 * @param kaMaxRetries    set the number of retries before connection is assumed dead
 */
np_error_code nc_keep_alive_set_settings(struct np_platform* pl, struct nc_keep_alive_context* ctx,
                                         uint16_t kaInterval, uint8_t kaRetryInterval, uint8_t kaMaxRetries);

#endif //NC_KEEP_ALIVE_H
