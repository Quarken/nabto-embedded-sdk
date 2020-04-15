#pragma once

#include <platform/np_platform.h>
#include <modules/libevent/nm_libevent.h>
#include <modules/logging/test/nm_logging_test.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>

#include <event2/event.h>
#include <event.h>



namespace nabto {
namespace test {

class TestPlatformLibevent : public TestPlatform {
 public:
    TestPlatformLibevent() {
        eventBase_ = event_base_new();
    }

    ~TestPlatformLibevent() {
        event_base_free(eventBase_);
    }

    virtual void init()
    {
        np_platform_init(&pl_);
        np_event_queue_init(&pl_, &TestPlatformLibevent::eventQueueExecutorNotify, this);
        nm_logging_test_init();
        np_communication_buffer_init(&pl_);
        nm_libevent_init(&pl_, &libeventContext_, eventBase_);
        nm_dtls_cli_init(&pl_);
        nm_dtls_srv_init(&pl_);
    }

    void deinit()
    {
        nm_libevent_deinit(&libeventContext_);
    }

    static void eventQueueExecutorNotify(void* userData)
    {
        TestPlatformLibevent* tp = (TestPlatformLibevent*)userData;
        event_base_loopbreak(tp->eventBase_);
    }

    static void timeoutCb(evutil_socket_t fd, short events, void* userData)
    {
        TestPlatformLibevent* tp = (TestPlatformLibevent*)userData;
        event_base_loopbreak(tp->eventBase_);
    }

    virtual void run()
    {
        struct event timeoutEvent;
        evtimer_assign(&timeoutEvent, eventBase_, &TestPlatformLibevent::timeoutCb, this);

        while (true) {
            if (stopped_) {
                //deinit();
                return;
            }
            np_event_queue_execute_all(&pl_);
            if (np_event_queue_has_timed_event(&pl_)) {
                uint32_t ms = np_event_queue_next_timed_event_occurance(&pl_);
                struct timeval tv;
                tv.tv_sec = ms/1000;
                tv.tv_usec = (ms % 1000) * 1000;
                evtimer_add(&timeoutEvent, &tv);

                if (stopped_) {
                    return;
                }
                event_base_loop(eventBase_, EVLOOP_ONCE);
                evtimer_del(&timeoutEvent);
            } else {
                if (stopped_) {
                    return;
                }
                event_base_loop(eventBase_, EVLOOP_NO_EXIT_ON_EMPTY);
            }
        }
    }

    virtual void stop()
    {
        stopped_ = true;
        event_base_loopbreak(eventBase_);
        deinit();
    }

    struct np_platform* getPlatform() {
        return &pl_;
    }

 private:
    struct np_platform pl_;
    struct event_base* eventBase_;
    struct nm_libevent_context libeventContext_;
    bool stopped_ = false;

};

} } // namespace
