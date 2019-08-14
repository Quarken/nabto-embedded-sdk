#include "nabto_device_iam.h"
#include "nabto/nabto_device.h"
#include "nabto/nabto_device_experimental.h"

#include "nabto_device_defines.h"
#include "nabto_device_coap.h"
#include "nabto_device_future.h"
#include "nabto_api_future_queue.h"
#include <core/nc_iam_policy.h>
#include <core/nc_iam.h>
#include <core/nc_iam_dump.h>

#include <stdlib.h>

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_dump(NabtoDevice* device, uint64_t* version, void* buffer, size_t bufferLength, size_t* used)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_dump(&dev->core.iam, version, buffer, bufferLength, used);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

// Load iam state from a cbor file.
NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_load(NabtoDevice* device, void* cbor, size_t cborLength)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_load(&dev->core.iam, cbor, cborLength);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

void iamChanged(const np_error_code ec, void* userData)
{

    struct nabto_device_context* dev = (struct nabto_device_context*)userData;
    if (dev->iamChangedFuture) {
        nabto_api_future_set_error_code(dev->iamChangedFuture, nabto_device_error_core_to_api(ec));
        nabto_api_future_queue_post(&dev->queueHead, dev->iamChangedFuture);
        dev->iamChangedFuture = NULL;
    }
}

NabtoDeviceFuture* NABTO_DEVICE_API
nabto_device_iam_listen_for_changes(NabtoDevice* device, uint64_t version)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    NabtoDeviceFuture* fut = NULL;

    nabto_device_threads_mutex_lock(dev->eventMutex);

    fut = nabto_device_future_new(device);
    if (fut) {
        if (dev->iamChangedFuture != NULL) {
            nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
            nabto_api_future_queue_post(&dev->queueHead, fut);
        } else {
            ec = nc_iam_set_change_callback(&dev->core.iam, iamChanged, dev);
            if (ec) {
                nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(ec));
                nabto_api_future_queue_post(&dev->queueHead, fut);
            } else {
                dev->iamChangedFuture = fut;
            }
        }
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return fut;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_check_action(NabtoDevice* device, NabtoDeviceConnectionRef connectionRef, const char* action)
{
    return nabto_device_iam_check_action_attributes(device, connectionRef, action, NULL, 0);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_check_action_attributes(NabtoDevice* device, NabtoDeviceConnectionRef connectionRef, const char* action, void* attributesCbor, size_t cborLength)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nc_client_connection* connection = nc_device_connection_from_ref(&dev->core, connectionRef);
    ec = nc_iam_check_access(connection, action, attributesCbor, cborLength);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_set_default_role(NabtoDevice* device, const char* role)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_set_default_role(&dev->core.iam, role);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

// add a user to the iam system
NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_create(NabtoDevice* device, const char* user)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_create_user(&dev->core.iam, user);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_delete(NabtoDevice* device, const char* user)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_delete_user(&dev->core, user);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_add_role(NabtoDevice* device, const char* user, const char* role)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_user_add_role(&dev->core.iam, user, role);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_remove_role(NabtoDevice* device, const char* user, const char* role)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_user_remove_role(&dev->core.iam, user, role);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);

}

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_list(NabtoDevice* device, void* cbor, size_t cborLength, size_t* used)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_list_users(&dev->core.iam, cbor, cborLength, used);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_get(NabtoDevice* device, const char* user, void* cbor, size_t cborLength, size_t* used)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_user_get(&dev->core.iam, user, cbor, cborLength, used);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_add_fingerprint(NabtoDevice* device, const char* user, const char* fingerprint)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_user_add_fingerprint(&dev->core.iam, user, fingerprint);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_remove_fingerprint(NabtoDevice* device, const char* user, const char* fingerprint)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_user_remove_fingerprint(&dev->core.iam, user, fingerprint);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_list(NabtoDevice* device, void* buffer, size_t bufferLength, size_t* used)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_list_roles(&dev->core.iam, buffer, bufferLength, used);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_get(NabtoDevice* device, const char* role, void* buffer, size_t bufferLength, size_t* used)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_role_get(&dev->core.iam, role, buffer, bufferLength, used);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_create(NabtoDevice* device, const char* role)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_create_role(&dev->core.iam, role);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_delete(NabtoDevice* device, const char* role)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_delete_role(&dev->core.iam, role);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_add_policy(NabtoDevice* device, const char* role, const char* policy)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_role_add_policy(&dev->core.iam, role, policy);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_deivce_iam_roles_remove_policy(NabtoDevice* device, const char* role, const char* policy)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_role_remove_policy(&dev->core.iam, role, policy);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}


NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policies_create(NabtoDevice* device, const char* name, void* cbor, size_t cborLength)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_cbor_policy_create(&dev->core.iam, name, cbor, cborLength);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policies_delete(NabtoDevice* device, const char* policy)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_policy_delete(&dev->core.iam, policy);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}


NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policies_get(NabtoDevice* device, const char* policy, void* buffer, size_t bufferLength, size_t* used)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nc_iam_policy_get(&dev->core.iam, policy, buffer, bufferLength, used);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policies_list(NabtoDevice* device, void* buffer, size_t bufferLength, size_t* used)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_list_policies(&dev->core.iam, buffer, bufferLength, used);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}