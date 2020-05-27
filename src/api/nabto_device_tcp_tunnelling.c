#include <nabto/nabto_device.h>

#include "nabto_device_defines.h"
#include <api/nabto_device_error.h>
#include <platform/np_error_code.h>
#include <modules/tcp_tunnel/nm_tcp_tunnel.h>

<<<<<<< Updated upstream
=======
#if defined(HAVE_WINSOCK2_H)
#include <Winsock2.h>
#endif

#if defined(HAVE_ARPA_INET_H)
#include <arpa/inet.h>
#endif

#if defined(ESP_PLATFORM)
#include <lwip/sockets.h>
#endif


>>>>>>> Stashed changes
NabtoDeviceError NABTO_DEVICE_API
nabto_device_add_tcp_tunnel_service(NabtoDevice* device, const char* serviceId, const char* serviceType, const char* host, uint16_t port)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    struct np_ip_address address;
    if (!np_ip_address_read_v4(host, &address)) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }

    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nm_tcp_tunnel_service* service = nm_tcp_tunnel_service_create(&dev->tcpTunnels);
    nm_tcp_tunnel_service_init(service, serviceId, serviceType, &address, port);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_remove_tcp_tunnel_service(NabtoDevice* device, const char* serviceId)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nm_tcp_tunnel_service_destroy_by_id(&dev->tcpTunnels, serviceId);
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return nabto_device_error_core_to_api(ec);
}
