#pragma once

#include <android/log.h>
#include <sys/system_properties.h>
#include <time.h>

#include <atomic>
#include <cstdint>
#include <cstring>

// Shared runtime debug toggle for all ColorOS 17 tanzanite AIDL HAL bridges.
// Default (unset or "0"): only 1-line boot banners (BRIDGE_LOG_BOOT) and real
// errors (ALOGE) are logged; verbose ALOGI / ALOGW runtime logs are silenced.
// Toggle live at runtime without restarting services:
//   adb shell setprop persist.vendor.cos.bridge.debug 1   # enable verbose logs
//   adb shell setprop persist.vendor.cos.bridge.debug 0   # silence verbose logs

namespace cos_bridge_log {

static constexpr const char* kDebugPropName = "persist.vendor.cos.bridge.debug";

inline bool parseTruthy(const char* v) {
    if (!v || !v[0]) return false;
    return (v[0] == '1' && v[1] == '\0') ||
           strcmp(v, "true") == 0 ||
           strcmp(v, "on") == 0 ||
           strcmp(v, "yes") == 0;
}

inline bool isDebugEnabled() {
    static std::atomic<const prop_info*> sPi{nullptr};
    static std::atomic<int64_t> sNextCheckSec{0};
    static std::atomic<bool> sEnabled{false};

    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    int64_t now = static_cast<int64_t>(ts.tv_sec);
    int64_t nextCheck = sNextCheckSec.load(std::memory_order_relaxed);
    if (now < nextCheck) {
        return sEnabled.load(std::memory_order_relaxed);
    }
    sNextCheckSec.store(now + 1, std::memory_order_relaxed);

    const prop_info* pi = sPi.load(std::memory_order_acquire);
    if (!pi) {
        pi = __system_property_find(kDebugPropName);
        if (!pi) {
            sEnabled.store(false, std::memory_order_relaxed);
            return false;
        }
        sPi.store(pi, std::memory_order_release);
    }

    bool enabled = false;
    __system_property_read_callback(
        pi,
        [](void* cookie, const char*, const char* value, uint32_t) {
            *static_cast<bool*>(cookie) = parseTruthy(value);
        },
        &enabled);
    sEnabled.store(enabled, std::memory_order_relaxed);
    return enabled;
}

}  // namespace cos_bridge_log

#define BRIDGE_DEBUG_ENABLED() (::cos_bridge_log::isDebugEnabled())

#define BRIDGE_LOG_BOOT(...) \
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#define ALOGI(...)                                                        \
    do {                                                                  \
        if (BRIDGE_DEBUG_ENABLED()) {                                     \
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__);  \
        }                                                                 \
    } while (0)

#define ALOGW(...)                                                        \
    do {                                                                  \
        if (BRIDGE_DEBUG_ENABLED()) {                                     \
            __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__);  \
        }                                                                 \
    } while (0)

#define ALOGE(...) \
    __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
