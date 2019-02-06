#ifndef NABTO_DEVICE_DEFINES_H
#define NABTO_DEVICE_DEFINES_H

#include "nabto_device_threads.h"

#include <platform/np_platform.h>
#include <core/nc_device.h>

void nabto_api_future_set_error_code(NabtoDeviceFuture* future, const NabtoDeviceError ec);
NabtoDeviceError nabto_device_error_core_to_api(np_error_code ec);

struct nabto_device_context {
    struct np_platform pl;
    struct nc_device_context core;

    struct nabto_device_thread* coreThread;
    struct nabto_device_thread* networkThread;
    struct nabto_device_mutex* eventMutex;
    struct nabto_device_condition* eventCond;
    
    bool closing;

    NabtoDeviceFuture* queueHead;

    char appName[33];
    char appVersion[33];

    char* productId;
    char* deviceId;
    char* serverUrl;
    char* publicKey;
    char* privateKey;

    NabtoDeviceFuture* closeFut;
};



#endif //NABTO_DEVICE_DEFINES_H