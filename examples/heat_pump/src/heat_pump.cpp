#include "heat_pump.hpp"
#include "json_config.hpp"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include "button_press.hpp"

void HeatPump::init() {
    listenForConnectionEvents();
    listenForDeviceEvents();

    persisting_.loadUsersIntoIAM(fingerprintIAM_);

    fingerprintIAM_.enableButtonPairing([](std::string fingerprint, std::function<void (bool accepted)> cb) {
            std::cout << "Allow the client with the fingerprint " << fingerprint << " to pair with the device? [y/n]" << std::endl;
            nabto::ButtonPress::wait(std::chrono::seconds(60), cb);
        });

    fingerprintIAM_.setUnpairedRole("Unpaired");
    fingerprintIAM_.setOwnerRole("Owner");
    fingerprintIAM_.setGuestRole("Guest");
}

bool validate_config(const json& config) {
    try {
        config["ProductId"].get<std::string>();
        config["DeviceId"].get<std::string>();
        config["Server"].get<std::string>();
        config["PrivateKey"].get<std::string>();
    } catch (std::exception& e) {
        return false;
    }
    return true;
}

void HeatPump::setMode(Mode mode)
{
    persisting_.setHeatPumpMode(modeToString(mode));
    persisting_.save();
}
void HeatPump::setTarget(double target)
{
    persisting_.setHeatPumpTarget(target);
    persisting_.save();
}

void HeatPump::setPower(bool power)
{
    persisting_.setHeatPumpPower(power);
    persisting_.save();
}

const char* HeatPump::modeToString(HeatPump::Mode mode)
{
    switch (mode) {
        case HeatPump::Mode::COOL: return "COOL";
        case HeatPump::Mode::HEAT: return "HEAT";
        case HeatPump::Mode::FAN: return "FAN";
        case HeatPump::Mode::DRY: return "DRY";
        default: return "UNKNOWN";
    }
}

void HeatPump::startWaitEvent()
{
    nabto_device_listener_connection_event(connectionEventListener_, connectionEventFuture_, &connectionRef_, &connectionEvent_);
    nabto_device_future_set_callback(connectionEventFuture_, &HeatPump::connectionEvent, this);
}

void HeatPump::connectionEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData)
{
    HeatPump* hp = (HeatPump*)userData;
    if (err != NABTO_DEVICE_EC_OK) {
        std::cout << "Connection event called back with error: " << err << std::endl;
        return;
    } else {
        if (hp->connectionEvent_ == NABTO_DEVICE_CONNECTION_EVENT_OPENED) {
            std::cout << "New connection opened with reference: " << hp->connectionRef_ << std::endl;
        } else if (hp->connectionEvent_ == NABTO_DEVICE_CONNECTION_EVENT_CLOSED) {
            std::cout << "Connection with reference: " << hp->connectionRef_ << " was closed" << std::endl;
        } else if (hp->connectionEvent_ == NABTO_DEVICE_CONNECTION_EVENT_CHANNEL_CHANGED) {
            std::cout << "Connection with reference: " << hp->connectionRef_ << " changed channel" << std::endl;
        } else {
            std::cout << "Unknown connection event: " << hp->connectionEvent_ << " on connection reference: " << hp->connectionRef_ << std::endl;
        }
    }
    hp->startWaitEvent();

}

void HeatPump::listenForConnectionEvents()
{
    NabtoDeviceError ec = nabto_device_connection_events_init_listener(device_, connectionEventListener_);
    if (ec) {
        std::cerr << "Failed to init connection events listener" << std::endl;
        return;
    }
    startWaitEvent();
}

void HeatPump::startWaitDevEvent()
{
    nabto_device_listener_device_event(deviceEventListener_, deviceEventFuture_, &deviceEvent_);
    nabto_device_future_set_callback(deviceEventFuture_, &HeatPump::deviceEvent, this);
}

void HeatPump::deviceEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData)
{
    HeatPump* hp = (HeatPump*)userData;
    if (err != NABTO_DEVICE_EC_OK) {
        std::cout << "Device event called back with error: " << err << std::endl;

        return;
    } else {
        if (hp->deviceEvent_ == NABTO_DEVICE_EVENT_ATTACHED) {
            std::cout << "Device is now attached" << std::endl;
        } else if (hp->deviceEvent_ == NABTO_DEVICE_EVENT_DETACHED) {
            std::cout << "Device is now detached" << std::endl;
        } else {
            std::cout << "Unknown device event: " << hp->deviceEvent_ << std::endl;
        }
    }
    hp->startWaitDevEvent();

}

void HeatPump::listenForDeviceEvents()
{
    NabtoDeviceError ec = nabto_device_device_events_init_listener(device_, deviceEventListener_);
    if (ec) {
        std::cerr << "Failed to initialize device events listener" << std::endl;
        return;
    }
    startWaitDevEvent();
}
