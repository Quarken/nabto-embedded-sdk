#ifndef NABTO_API_FUTURE_QUEUE_H
#define NABTO_API_FUTURE_QUEUE_H

#include <nabto/nabto_device.h>

struct nabto_device_future;

void nabto_api_future_queue_execute_all(struct nabto_device_future** queue);

void nabto_api_future_queue_post(struct nabto_device_future** head, struct nabto_device_future* future);

#endif // NABTO_API_FUTURE_QUEUE_H
