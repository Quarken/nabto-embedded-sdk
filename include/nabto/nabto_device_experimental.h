#ifndef _NABTO_DEVICE_EXPERIMENTAL_H_
#define _NABTO_DEVICE_EXPERIMENTAL_H_

#include "nabto_device.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/****************
 * Listener API *
 ****************/

typedef struct NabtoDeviceListener_ NabtoDeviceListener;

/**
 * Free a listener, effectivly cancelling active listening on a
 * resource. To ensure there is no concurrency issues, this should
 * always be called while resolving a future for this listener.
 *
 * @param listener  Listener to be freed
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_listener_free(NabtoDeviceListener* listener);

/**
 * Stop a listener, effectivly cancelling active listening on a
 * resource. This is concurrency safe, and can be called
 * anywhere. This will trigger an event with error code
 * NABTO_DEVICE_EC_STOPPED
 *
 * @param listener  Listener to be freed
 * @return NABTO_EC_OK on success
 *
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_listener_stop(NabtoDeviceListener* listener);

// todo this returns error code and takes future ** as argument, do this all other places
/**
 * Create new future for Listener, called once ready to receive next
 * event from Listener. (eg. with connection event listener : call
 * this once ref and event arguments are ready to be overwritten by
 * next event.)
 *
 * @param listener       Listener to listen for
 * @param future         The future resolved once the next event is available
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if listener already have a future
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if future or and underlying structure could not be allocated
 *         NABTO_DEVICE_EC_ABORTED if underlying service stopped (eg. if device closed)
 *         NABTO_DEVICE_EC_STOPPED if the listener was stopped
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_listener_listen(NabtoDeviceListener* listener, NabtoDeviceFuture** future);

/**
 * Set the server port.
 * If not set it will default to 4433
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_server_port(NabtoDevice* device, uint16_t port);

/**************
 * Connection *
 **************/

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_client_fingerprint_hex(NabtoDevice* device, NabtoDeviceConnectionRef ref, char** fp);

typedef int NabtoDeviceConnectionEvent;

extern const NabtoDeviceConnectionEvent NABTO_DEVICE_CONNECTION_EVENT_OPENED;
extern const NabtoDeviceConnectionEvent NABTO_DEVICE_CONNECTION_EVENT_CLOSED;
extern const NabtoDeviceConnectionEvent NABTO_DEVICE_CONNECTION_EVENT_CHANNEL_CHANGED;

NABTO_DEVICE_DECL_PREFIX NabtoDeviceListener* NABTO_DEVICE_API
nabto_device_connection_events_listener_new(NabtoDevice* device, NabtoDeviceConnectionRef* ref, NabtoDeviceConnectionEvent* event);

/*****************
 * Device Events *
 *****************/

typedef int NabtoDeviceEvent;

extern const NabtoDeviceEvent NABTO_DEVICE_EVENT_ATTACHED;
extern const NabtoDeviceEvent NABTO_DEVICE_EVENT_DETACHED;
extern const NabtoDeviceEvent NABTO_DEVICE_EVENT_FAILURE;

NABTO_DEVICE_DECL_PREFIX NabtoDeviceListener* NABTO_DEVICE_API
nabto_device_events_listener_new(NabtoDevice* device, NabtoDeviceEvent* event);

/********
 * Util *
 ********/
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_experimental_util_create_private_key(NabtoDevice* device, char** key);



NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_experimental_util_free(void* data);

/*******
 * IAM *
 *******/

extern const NabtoDeviceError NABTO_DEVICE_EC_IAM_DENY;

extern const NabtoDeviceError NABTO_DEVICE_EC_INVALID_ARGUMENT;
extern const NabtoDeviceError NABTO_DEVICE_EC_NOT_FOUND;

/**
 * IAM decision context for a query, the environment contains all the
 * neccessary attributes and user information to decide if the given
 * action is allowed.
 */
typedef struct NabtoDeviceIamEnv_ NabtoDeviceIamEnv;

/**
 * Callback when the iam system has been modified. The application can choose to persist the changes.
 */
typedef void (*NabtoDeviceIamChangedCallback)(void* userData);


/**
 * Override iam check function This function is synchroniously called
 * from the code, It's not allowed to call NabtoDevice api functions
 * from this function.
 */

/**
 * IAM check access callback function.
 *
 * @param attributes  cbor encoded attributes, if NULL no attributes is provided.
 * @return NABTO_DEVICE_EC_OK if access is allowed.
 *         NABTO_DEVICE_EC_IAM_DENY if access is not allowed.
 */
typedef NabtoDeviceError (*NabtoDeviceIAMCheckAccessCallback)(NabtoDeviceConnectionRef connectionReference, const char* action, void* attributes, size_t attributesLength, void* userData);

/**
 * Override iam check function This function is synchroniously called
 * from the core, It's not allowed to call other NabtoDevice api
 * functions from this function. Since the caller will have a lock on
 * the system.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_override_check_access_implementation(NabtoDevice* device, NabtoDeviceIAMCheckAccessCallback cb, void* userData);

/**
 * Dump all iam state in a single cbor object such that it can be
 * persisted.
 *
 * @param version  the current version of the iam database
 * @param buffer   if NULL or too small the function returns OUT_OF_MEMORY
 *                 and used is set to the required buffer size
 * @return
 *  NABTO_DEVICE_EC_OK             If ok.
 *  NABTO_DEVICE_EC_OUT_OF_MEMORY  If the buffer is too small.
 *  NABTO_DEVICE_EC_FAILED         If an unknown error has happened.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_dump(NabtoDevice* device, uint64_t* version, void* buffer, size_t bufferLength, size_t* used);

/**
 * Load a CBOR state of the IAM module
 *
 * CBOR format
 * {
 *  "Users": {
 *    "UserName": (see nabto_device_iam_users_get)
 *  },
 *  "Roles": {
 *    "RoleName": (see nabto_device_iam_roles_get)
 *  },
 *  "Policies": {
 *    "PolicyName": (see nabto_device_iam_policies_get)
 *  }
 *
 * }
 *
 * @return
 *  NABTO_DEVICE_EC_IAM_INVALID_*  if the data is invalid.
 *  NABTO_DEVICE_EC_OK  if the data is ok and loaded into the system.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_load(NabtoDevice* device, void* cbor, size_t cborLength);

/**
 * Listen for changes in the iam module. If version is different from
 * the current version, it will resolve as soon as possible.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceFuture* NABTO_DEVICE_API
nabto_device_iam_listen_for_changes(NabtoDevice* device, uint64_t version);

/**
 * Decide if action is allowed given the decision context.
 *
 * The cbor data is a key value map with attribute:(string|number) pairs. e.g.
 *
 * {
 *   "Pairing:IsPaired": 0,
 *   "Pairing:Password": "..."
 * }
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the action is allowed.
 *  NABTO_DEVICE_EC_IAM_DENY if the action is denied by an iam policy.
 *  NABTO_DEVICE_EC_IAM_NONE if there's no policies matching the action and attributes.
 *  NABTO_DEVICE_EC_* if some error occurs in checking the action and attributes against the iam system.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_check_action_attributes(NabtoDevice* device, NabtoDeviceConnectionRef connectionRef, const char* action, void* attributesCbor, size_t cborLength);

/**
 * Same as nabto_device_iam_check_action_attributes but without attributes
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_check_action(NabtoDevice* device, NabtoDeviceConnectionRef connectionRef, const char* action);

/**
 * Set a default role for connections where no fingerprint is found in the iam system.
 * @return
 *  NABTO_DEVICE_EC_OK if role was set.
 *  NABTO_DEVICE_EC_NOT_FOUND if the role could not be found.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_set_default_role(NabtoDevice* device, const char* role);

/**
 * Add a user to the system which is not meant to be persisted in the
 * iam system. This is usually called from an coap resource which
 * validates a JWT access token, the jwt token then defines which
 * roles the user has.
 */
// TODO
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_add_federated_user(NabtoDevice* device, const char* user);

/**
 * Set the user a connection is associated with, this is often used
 * together with jwt and a federated user.
 */
// TODO
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_connection_set_user(NabtoDevice* device, NabtoDeviceConnectionRef connectionRef, const char* user);

/**
 * Add a user to the IAM system.
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the user was added to the system.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_create(NabtoDevice* device, const char* user);

/**
 * Delete a user from the IAM system
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the user was deleted.
 *  NABTO_DEVICE_EC_IN_USE if the user is used by a connection.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_delete(NabtoDevice* device, const char* user);

/**
 * Get a user as a CBOR representation
 *
 * CBOR format
 * {
 *   Roles: ["Role1","Role2",....],
 *   Fingerprints: ["Fp1", "Fp2",...]
 * }
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the user was found and could be stored in the supplied buffer.
 *  NABTO_DEVICE_EC_OUT_OF_MEMORY if the buffer is too small, used is set to the required buffer size.
 *  NABTO_DEVICE_EC_NOT_FOUND if the user is not found.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_get(NabtoDevice* device, const char* user, void* cbor, size_t cborLength, size_t* used);

/**
 * List users
 *
 * CBOR format
 * ["User1", "User2",...]
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff ok
 *  NABTO_DEVICE_EC_OUT_OF_MEMORY if the buffer is too small, used is set to the required buffer size.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_list(NabtoDevice* device, void* cbor, size_t cborLength, size_t* used);

/**
 * Add a role to a user
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the role is added to the user
 *  NABTO_DEVICE_EC_NOT_FOUND if user or role does not exists
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_add_role(NabtoDevice* device, const char* user, const char* role);

/**
 * Remoce a role to a user
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the role is removed from the user
 *  NABTO_DEVICE_EC_NOT_FOUND if user or role does not exists
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_remove_role(NabtoDevice* device, const char* user, const char* role);

/**
 * Add a fingerprint to a user
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the fingerprint is added to the user
 *  NABTO_DEVICE_EC_NOT_FOUND if user or fingerprint does not exists
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_add_fingerprint(NabtoDevice* device, const char* user, const char* fingerprint);

/**
 * Remoce a fingerprint to a user
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the fingerprint is removed from the user
 *  NABTO_DEVICE_EC_NOT_FOUND if user or fingerprint does not exists
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_remove_fingerprint(NabtoDevice* device, const char* user, const char* fingerprint);

/**
 * List roles in the IAM system
 *
 * CBOR format
 * ["Role1", "Role2", ...]
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the list roles could be stored in the supplied buffer.
 *  NABTO_DEVICE_EC_OUT_OF_MEMORY if the buffer is too small, used is set to the required buffer size.
 *
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_list(NabtoDevice* device, void* buffer, size_t bufferLength, size_t* used);

/**
 * Get a role as a CBOR representation
 *
 * CBOR format
 * {
 *   Policies: ["Policy1","Policy2",....],
 * }
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the role was found and could be stored in the supplied buffer.
 *  NABTO_DEVICE_EC_OUT_OF_MEMORY if the buffer is too small, used is set to the required buffer size.
 *  NABTO_DEVICE_EC_NOT_FOUND if the role is not found.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_get(NabtoDevice* device, const char* role, void* buffer, size_t bufferLength, size_t* used);

/**
 * Create a Role
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the role was created
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_create(NabtoDevice* device, const char* role);

/**
 * Delete a role
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the role was deleted
 *  NABTO_DEVICE_EC_NOT_FOUND if the role was not found
 *  NABTO_DEVICE_EC_IN_USE if the role is in use, e.g. as a default role on the system
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_delete(NabtoDevice* device, const char* role);

/**
 * Add a policy to a role
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the policy was added to the role.
 *  NABTO_DEVICE_EC_NOT_FOUND if the role or policy could not be found.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_add_policy(NabtoDevice* device, const char* role, const char* policy);

/**
 * Remove a policy from a role
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the policy was removed from the role.
 *  NABTO_DEVICE_EC_NOT_FOUND if the policy or role is not found.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_deivce_iam_roles_remove_policy(NabtoDevice* device, const char* role, const char* policy);


/**
 * Create or update a policy.
 *
 * If the policy does already exists the current policy is overwritten
 * by the new policy. If no policy exists with the given name, a new
 * one is created.
 *
 * CBOR format
 * {
 *   "Version": 1,
 *   "Statements": [
 *     {
 *       "Allow": (true|false), (required)
 *       "Actions": ["Module1:ActionX", "Module2:ActionY", ...], (required)
 *       "Conditions": [
 *          {"StringEqual": {"AttributeName": "string"} },
 *          {"NumberEqual": {"AttributeName": 42 } },
 *          {"AttributeEqual": {"AttributeName": "AttributeName" } }
 *       ]
 *     }
 *   ]
 * }
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the policy is loaded into the IAM system.
 *  NABTO_DEVICE_EC_INVALID_POLICY if the policy is invalid.
 *  NABTO_DEVICE_EC_INVALID_STATEMENT if the statement is invalid.
 *  NABTO_DEVICE_EC_INVALID_ACTION if an action is invalid.
 *  NABTO_DEVICE_EC_INVALID_CONDITION if a condition is invalid.
 *  NABTO_DEVICE_EC_OUT_OF_MEMORY if the policy cannot be stored in the IAM module. *
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policies_create(NabtoDevice* device, const char* policy, void* cbor, size_t cborLength);

/**
 * Delete an IAM policy
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the policy is deleted
 *  NABTO_DEVICE_EC_NOT_FOUND if the policy does not exists.
 *  NABTO_DEVICE_EC_IN_USE if the policy is in use by a role.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policies_delete(NabtoDevice* device, const char* policy);

/**
 * Get an IAM policy.
 *
 * CBOR format
 * see nabto_device_iam_policies_create.
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the policy is found and could be stored in the buffer.
 *  NABTO_DEVICE_EC_OUT_OF_MEMORY if the buffer is too small.
 *  NABTO_DEVICE_EC_NOT_FOUND if the policy could not be found.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policies_get(NabtoDevice* device, const char* policy, void* buffer, size_t bufferLength, size_t* used);

/**
 * List iam policies
 *
 * CBOR format
 * ["Policy1","Policy2"]
 *
 * @return
 *  NABTO_DEVICE_EC_OK iff the policies is stored in the buffer
 *  NABTO_DEVICE_EC_OUT_OF_MEMORY if the buffer is too small.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policies_list(NabtoDevice* device, void* buffer, size_t bufferLength, size_t* used);


/***************
 * MDNS Server *
 ***************/

/**
 * Enable the optional mdns server/responder. The server is started when the
 * device is started. Mdns has to be enabled before the device is
 * started. The responder is stopped when the device is closed.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_enable_mdns(NabtoDevice* device);


/******************
 * TCP Tunnelling *
 ******************/

/**
 * Enable TCP tunnelling in the device.
 *
 * Tcp tunnelling is a feature which allows clients to tunnel tcp
 * traffic over a nabto connection to the device. TCP tunnelling is
 * stopped when the device is closed.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_enable_tcp_tunnelling(NabtoDevice* device);

#ifdef __cplusplus
} // extern c
#endif

#endif
