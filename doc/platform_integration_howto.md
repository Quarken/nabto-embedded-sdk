
# Platform Integration Howto

This document is a short guide on how to create and integration to a
new platform for Nabto Edge.

## Overall architecture.

Nabto Edge needs to know about the underlying platform it is running on.
The way to "inform" Nabto Edge about this platform is to implement a list
of function and supply Nabto Edge with these functions. The list consist of
a list of function defined in .h files (empty function) and function pointers
that are supplied to Nabto Edge via setup of structs.


## Components which is needed for a custom platform.

To create the `nabto_device` library several things needs to be
implemented.

### `api/nabto_device_platform.h`

This file contains 3 functions, an init, deinit and a stop
function ie. functions needed for bootstrap and teardown of the system.
These functions is called when a device is created,
destroyed and stopped. The purpose of these functions is to setup the
`platform/np_platform.h` (described later) struct's and to create the overall functionality which
is required to run such a platform. The actual initialization of the platform happens from the
`nabto_device_init_platform` function. See `doc/np_platform.md` and the header file for further
information.

### `platform/np_platform.h`

The `platform/np_platform.h` contains specification of all the platform specific implementations.
These implentations consist of functions that is used by the core functionality inside Nabto Edge.
The .h files consist of several independent modules encapsulated in struct's.
Each struct consists of a list of function pointers that needs to be setup in the bootstrap process (i.e the 'nabto_device_init_platform' function).

Each module in `np_platform.h` should be implemented or an implementation which
is working on the desired platform should be choosen. This example works on UNIX systems so
modules which works on such a system has been choosen. 


### `api/nabto_device_threads.h`

The api `nabto/nabto_device.h` is a thread safe API, which also
exposes functionality which can block the system. The system currently 
also need to have a thread implementation. The thread
abstraction defindes, threads, mutexes and condition variables. See
the header file for more information or take a look at the existing
implementations in the `src/modules/threads` folder.