# nabto-embedded-sdk

Nabto embedded SDK

## Building and Testing

mkdir build
cd build
cmake ..
`./test_cpp/embedded_unit_test`


## Components

The source is split into several "components"

### `src/platform`

The platform folder contains a platform which is used to run the
core. The platform implements a set of functions which can schedule
events and several interfaces which is used for diverse features such
as udp communication, dns lookups, timestamps etc. See
`src/platform/np_platform.h` for futher information.

### `src/core`

The core is the nabto communication protocol, the core uses the
platform and implements the core of the embedded nabto communication
system.

### `src/modules`

Modules is the folder where modules for specific targets
exists. Modules can be for encryption, networking, timing, logging
etc.

### `nabto-common`

This folder contains some common functionality which is shared amongst
several components.

### `examples`

This folder contains examples for how the platform can be used.

### `apps`

This folder contains applications which can be used as they are.

### `platform_integration_example`

This folder contains an example of a custom implementation of the
`nabto/nabto_device.h` api.

### `include`

This folder has the public interface which the nabto_device api
exposes.
