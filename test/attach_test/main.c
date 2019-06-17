#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <platform/np_ip_address.h>
#include <core/nc_attacher.h>
#include <core/nc_client_connect.h>
#include <core/nc_client_connect_dispatch.h>
#include <core/nc_stun.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

const char* appVer = "0.0.1";
const char* appName = "Weather_app";
//const char* hostname = "a.devices.dev.nabto.net";
const char* hostname = "localhost";
const char* stunHost = "stun.nabto.net";

struct nc_attach_parameters attachParams;

const unsigned char devicePrivateKey[] =
"-----BEGIN EC PARAMETERS-----\r\n"
"BggqhkjOPQMBBw==\r\n"
"-----END EC PARAMETERS-----\r\n"
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEII2ifv12piNfHQd0kx/8oA2u7MkmnQ+f8t/uvHQvr5wOoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEY1JranqmEwvsv2GK5OukVPhcjeOW+MRiLCpy7Xdpdcdc7he2nQgh\r\n"
"0+aTVTYvHZWacrSTZFQjXljtQBeuJR/Gsg==\r\n"
"-----END EC PRIVATE KEY-----\r\n";

const unsigned char devicePublicKey[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIBaTCCARCgAwIBAgIJAOR5U6FNgvivMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMM\r\n"
"BW5hYnRvMB4XDTE4MDgwNzA2MzgyN1oXDTQ4MDczMDA2MzgyN1owEDEOMAwGA1UE\r\n"
"AwwFbmFidG8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARjUmtqeqYTC+y/YYrk\r\n"
"66RU+FyN45b4xGIsKnLtd2l1x1zuF7adCCHT5pNVNi8dlZpytJNkVCNeWO1AF64l\r\n"
"H8ayo1MwUTAdBgNVHQ4EFgQUjq36vzjxAQ7I8bMejCf1/m0eQ2YwHwYDVR0jBBgw\r\n"
"FoAUjq36vzjxAQ7I8bMejCf1/m0eQ2YwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO\r\n"
"PQQDAgNHADBEAiBF98p5zJ+98XRwIyvCJ0vcHy/eJM77fYGcg3J/aW+lIgIgMMu4\r\n"
"XndF4oYF4h6yysELSJfuiamVURjo+KcM1ixwAWo=\r\n"
"-----END CERTIFICATE-----\r\n";

uint8_t fp[] = {0xdd, 0x5f, 0xec, 0x4f, 0x27, 0xb5, 0x65, 0x7c, 0xb7, 0x5e, 0x5e, 0x24, 0x7f, 0xe7, 0x92, 0xcc};

struct test_context {
    int data;
};
struct np_platform pl;
struct nc_stream_manager_context streamManager;
struct nc_client_connect_dispatch_context dispatch;
struct nc_udp_dispatch_context udp;
struct nc_udp_dispatch_context secondaryUdp;
struct nc_attach_context attach;
struct nabto_stream* stream;
struct nc_stun_context stun;
struct nc_coap_server_context coap;
struct nc_rendezvous_context rendezvous;
uint8_t buffer[1500];

void stream_application_event_callback(nabto_stream_application_event_type eventType, void* data)
{
    NABTO_LOG_ERROR(0, "application event callback eventType: %s", nabto_stream_application_event_type_to_string(eventType));
    size_t readen = 0;
    size_t written = 0;
    nabto_stream_status status;
    status = nabto_stream_read_buffer(stream, buffer, 1500, &readen);
    if (status == NABTO_STREAM_STATUS_OK) {
        if (readen > 0) {
            nabto_stream_write_buffer(stream, buffer, readen, &written);
            NABTO_LOG_ERROR(0, "application event wrote %u bytes", written);
        }
    } else {
        status = nabto_stream_close(stream);
        if (status != NABTO_STREAM_STATUS_OK) {
            nabto_stream_release(stream);
        }
    }
}

void stream_listener(struct nabto_stream* incStream, void* data)
{
    NABTO_LOG_ERROR(0, "Test listener callback ");
    stream = incStream;
    nabto_stream_set_application_event_callback(stream, &stream_application_event_callback, data);
    nabto_stream_accept(stream);
}

void attachedCb(const np_error_code ec, void* data) {

    if (ec == NABTO_EC_OK) {
        NABTO_LOG_INFO(0, "DEVICE ATTACHED!! Received attached callback with NABTO_EC_OK");
    } else {
        NABTO_LOG_INFO(0, "DEVICE ATTACH FAILED!!! Received attached callback with ERROR %u", ec);
        exit(1);
    }
}

void connCreatedCb(const np_error_code ec, void* data) {
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "udp create failed");
        exit(1);
    }
    nc_stun_init(&stun, &pl, stunHost, &udp, &secondaryUdp);
    nc_udp_dispatch_set_client_connect_context(&udp, &dispatch);
    nc_attacher_async_attach(&attach, &pl, &attachParams, attachedCb, &data);
}

int main() {
    int nfds;

    attachParams.hostname = hostname;
    const char* deviceLbHost = getenv("DEVICE_LB_HOST");
    if (deviceLbHost) {
        attachParams.hostname = deviceLbHost;
    }

    np_platform_init(&pl);
    np_log_init();

    np_access_control_init(&pl);
    np_communication_buffer_init(&pl);
    np_udp_init(&pl);
    np_dtls_cli_init(&pl, devicePublicKey, strlen((const char*)devicePublicKey), devicePrivateKey, strlen((const char*)devicePrivateKey));
    np_dtls_srv_init(&pl, devicePublicKey, strlen((const char*)devicePublicKey), devicePrivateKey, strlen((const char*)devicePrivateKey));
    np_ts_init(&pl);
    np_dns_init(&pl);

    struct test_context data;
    data.data = 42;

    nc_stream_manager_init(&streamManager, &pl);
    nc_coap_server_init(&pl, &coap);
    nc_client_connect_dispatch_init(&dispatch, &pl, &coap, &rendezvous, &streamManager);
    nc_stream_manager_set_listener(&streamManager, &stream_listener, &data);

    attachParams.appName = appName;
    attachParams.appVersion = appVer;

    nc_udp_dispatch_async_create(&udp, &pl, 0, &connCreatedCb, &data);
    attachParams.udp = &udp;

    while (true) {
        np_event_queue_execute_all(&pl);
        if (np_event_queue_is_event_queue_empty(&pl)) {
//            NABTO_LOG_ERROR(0, "Event queue not empty after emptying");
        }
        if (np_event_queue_has_timed_event(&pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&pl);
            nfds = pl.udp.timed_wait(ms);
        } else {
            nfds = pl.udp.inf_wait();
        }
        pl.udp.read(nfds);
    }

    exit(0);
}
