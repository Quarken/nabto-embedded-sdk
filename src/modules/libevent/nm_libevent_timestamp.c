#include "nm_libevent_timestamp.h"

#include <platform/np_platform.h>
#include <platform/np_timestamp.h>

#include <event2/event.h>

#if defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#endif

#if defined(HAVE_WINSOCK2_H)
#include <winsock2.h>
#endif




static uint32_t ts_now_ms(void* data);

static const struct np_timestamp_functions vtable = {
    .now_ms = &ts_now_ms
};


const struct np_timestamp_functions* nm_libevent_timestamp_functions()
{
    return &vtable;
}

uint32_t ts_now_ms(void* data)
{
    struct event_base* eventBase = data;
    struct timeval tv;
    event_base_gettimeofday_cached(eventBase, &tv);

    return ((((uint64_t)tv.tv_sec)*1000) + (((uint64_t)tv.tv_usec)/1000));
}
