#include "libevent_event_queue.h"

#include <api/nabto_device_threads.h>
#include <api/nabto_device_future.h>

#include <platform/np_logging.h>

#include <stdlib.h>

#include <event.h>
#include <event2/event.h>

#define LOG NABTO_LOG_MODULE_EVENT_QUEUE

static np_error_code create_event(void* data, np_event_callback cb, void* cbData, struct np_event** event);
static void destroy_event(struct np_event* event);
static void post(struct np_event* event);
static void post_maybe_double(struct np_event* event);

static np_error_code create_timed_event(void* data, np_timed_event_callback cb, void* cbData, struct np_timed_event** event);
static void destroy_timed_event(struct np_timed_event* event);

static void post_timed_event(struct np_timed_event* event, uint32_t milliseconds);
static void cancel(struct np_event* event);
static void cancel_timed_event(struct np_timed_event* timedEvent);

static void handle_timed_event(evutil_socket_t s, short events, void* data);
static void handle_event(evutil_socket_t s, short events, void* data);

struct libevent_event_queue {
    struct nabto_device_mutex* mutex;
    struct nabto_device_thread* coreThread;
    struct event_base* eventBase;
};

struct np_event {
    struct libevent_event_queue* eq;
    np_event_callback cb;
    void* data;
    struct event event;
};

struct np_timed_event {
    struct libevent_event_queue* eq;
    np_timed_event_callback cb;
    void* data;
    struct event event;
};


static struct np_event_queue_functions vtable = {
    .create_event = &create_event,
    .destroy_event = &destroy_event,
    .post = &post,
    .post_maybe_double = &post_maybe_double,
    .cancel = &cancel,
    .create_timed_event = &create_timed_event,
    .destroy_timed_event = &destroy_timed_event,
    .post_timed_event = &post_timed_event,
    .cancel_timed_event = &cancel_timed_event
};

struct np_event_queue libevent_event_queue_create(struct event_base* eventBase, struct nabto_device_mutex* mutex)
{
    struct libevent_event_queue* eq = calloc(1, sizeof(struct libevent_event_queue));
    eq->eventBase = eventBase;
    eq->mutex = mutex;
    struct np_event_queue obj;
    obj.vptr = &vtable;
    obj.data = eq;
    return obj;
}

void libevent_event_queue_destroy(struct np_event_queue* obj)
{
    free(obj->data);
}

void handle_timed_event(evutil_socket_t s, short events, void* data)
{
    NABTO_LOG_TRACE(LOG, "handle timed event");
    struct np_timed_event* timedEvent = data;

    struct libevent_event_queue* eq = timedEvent->eq;

    nabto_device_threads_mutex_lock(eq->mutex);
    timedEvent->cb(NABTO_EC_OK, timedEvent->data);
    nabto_device_threads_mutex_unlock(eq->mutex);

}

void handle_event(evutil_socket_t s, short events, void* data)
{
    NABTO_LOG_TRACE(LOG, "handle event");
    struct np_event* event = data;
    struct libevent_event_queue* eq = event->eq;

    nabto_device_threads_mutex_lock(eq->mutex);
    event->cb(event->data);
    nabto_device_threads_mutex_unlock(eq->mutex);
}

np_error_code create_event(void* data, np_event_callback cb, void* cbData, struct np_event** event)
{
    struct np_event* ev = calloc(1, sizeof(struct np_event));
    if (ev == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    struct libevent_event_queue* eq = data;
    ev->eq = eq;
    ev->cb = cb;
    ev->data = cbData;

    event_assign(&ev->event, eq->eventBase, -1, 0, &handle_event, ev);

    *event = ev;
    return NABTO_EC_OK;
}

void destroy_event(struct np_event* event)
{
    free(event);
}

void post(struct np_event* event)
{
    //NABTO_LOG_TRACE(LOG, "post event");
    //struct np_platform* pl = event->pl;
    //struct nabto_device_event_queue* eq = pl->eqData;
    event_active(&event->event, 0, 0);
}

void post_maybe_double(struct np_event* event)
{
    // TODO
    //struct np_platform* pl = event->pl;
    //struct nabto_device_event_queue* eq = pl->eqData;
    event_active(&event->event, 0, 0);
}

np_error_code create_timed_event(void* data, np_timed_event_callback cb, void* cbData, struct np_timed_event** event)
{
    struct np_timed_event* ev = calloc(1, sizeof(struct np_timed_event));
    if (ev == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    struct libevent_event_queue* eq = data;
    ev->eq = eq;
    ev->cb = cb;
    ev->data = cbData;

    event_assign(&ev->event, eq->eventBase, -1, 0, &handle_timed_event, ev);

    *event = ev;
    return NABTO_EC_OK;
}

void destroy_timed_event(struct np_timed_event* event)
{
    free(event);
}

void post_timed_event(struct np_timed_event* event, uint32_t milliseconds)
{
    //struct np_platform* pl = event->pl;
    //struct nabto_device_event_queue* eq = pl->eqData;
    struct timeval tv;
    tv.tv_sec = (milliseconds / 1000);
    tv.tv_usec = ((milliseconds % 1000) * 1000);
    event_add (&event->event, &tv);
}

void cancel(struct np_event* event)
{
    event_del(&event->event);
}

void cancel_timed_event(struct np_timed_event* timedEvent)
{
    event_del(&timedEvent->event);
}
