#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>
#include <android/log.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#define LOG_TAG "FodAidlBridge"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Platform LL-NDK libbinder_ndk symbols
extern "C" {
binder_status_t AServiceManager_addService(AIBinder* binder, const char* instance);
bool ABinderProcess_setThreadPoolMaxThreadCount(uint32_t numThreads);
void ABinderProcess_startThreadPool(void);
void ABinderProcess_joinThreadPool(void);
void AIBinder_markVintfStability(AIBinder* binder);
}

// ============================================================================
// Standard AOSP 64-bit hardware/fingerprint.h + hw_auth_token.h + Xiaomi extCmd
// Verified byte-for-byte against Xiaomi fingerprint.jiiov.so / libmifpext.so.
// ============================================================================

typedef struct __attribute__((__packed__)) {
    uint8_t version;
    uint64_t challenge;
    uint64_t user_id;
    uint64_t authenticator_id;
    uint32_t authenticator_type;  // network byte order (big-endian)
    uint64_t timestamp;           // network byte order (big-endian)
    uint8_t hmac[32];
} hw_auth_token_t;
static_assert(sizeof(hw_auth_token_t) == 69, "hw_auth_token_t must be 69 bytes");

typedef enum fingerprint_msg_type {
    FINGERPRINT_ERROR = -1,
    FINGERPRINT_ACQUIRED = 1,
    FINGERPRINT_TEMPLATE_ENROLLING = 3,
    FINGERPRINT_TEMPLATE_REMOVED = 4,
    FINGERPRINT_AUTHENTICATED = 5,
    FINGERPRINT_TEMPLATE_ENUMERATING = 6,
} fingerprint_msg_type_t;

typedef struct fingerprint_finger_id {
    uint32_t gid;
    uint32_t fid;
} fingerprint_finger_id_t;

typedef struct fingerprint_enroll {
    fingerprint_finger_id_t finger;
    uint32_t samples_remaining;
    uint64_t msg;
} fingerprint_enroll_t;

typedef struct fingerprint_removed {
    fingerprint_finger_id_t finger;
    uint32_t remaining_templates;
} fingerprint_removed_t;

typedef struct fingerprint_enumerated {
    fingerprint_finger_id_t finger;
    uint32_t remaining_templates;
} fingerprint_enumerated_t;

typedef struct fingerprint_acquired {
    int32_t acquired_info;
} fingerprint_acquired_t;

typedef struct fingerprint_authenticated {
    fingerprint_finger_id_t finger;
    hw_auth_token_t hat;
} fingerprint_authenticated_t;

typedef struct fingerprint_msg {
    fingerprint_msg_type_t type;
    union {
        int32_t error;
        fingerprint_enroll_t enroll;
        fingerprint_enumerated_t enumerated;
        fingerprint_removed_t removed;
        fingerprint_acquired_t acquired;
        fingerprint_authenticated_t authenticated;
    } data;
} fingerprint_msg_t;

static_assert(offsetof(fingerprint_msg_t, data) == 0x08, "fingerprint_msg_t.data must be at 0x08");
static_assert(offsetof(fingerprint_msg_t, data.authenticated.hat) == 0x10,
              "fingerprint_msg_t.data.authenticated.hat must be at 0x10");

typedef void (*fingerprint_notify_t)(const fingerprint_msg_t* msg);

struct hw_module_t;
struct hw_device_t;

typedef struct hw_module_methods_t {
    int (*open)(const struct hw_module_t* module, const char* id, struct hw_device_t** device);
} hw_module_methods_t;

typedef struct hw_module_t {
    uint32_t tag;
    uint16_t module_api_version;
    uint16_t hal_api_version;
    const char* id;
    const char* name;
    const char* author;
    struct hw_module_methods_t* methods;
    void* dso;
    uint64_t reserved[32 - 7];
} hw_module_t;

typedef struct hw_device_t {
    uint32_t tag;
    uint32_t version;
    struct hw_module_t* module;
    uint64_t reserved[12];
    int (*close)(struct hw_device_t* device);
} hw_device_t;

typedef struct fingerprint_device {
    hw_device_t common;
    fingerprint_notify_t notify;
    int (*set_notify)(struct fingerprint_device* dev, fingerprint_notify_t notify);
    uint64_t (*pre_enroll)(struct fingerprint_device* dev);
    int (*enroll)(struct fingerprint_device* dev, const hw_auth_token_t* hat,
                  uint32_t gid, uint32_t timeout_sec);
    int (*post_enroll)(struct fingerprint_device* dev);
    uint64_t (*get_authenticator_id)(struct fingerprint_device* dev);
    int (*cancel)(struct fingerprint_device* dev);
    int (*enumerate)(struct fingerprint_device* dev);
    int (*remove)(struct fingerprint_device* dev, uint32_t gid, uint32_t fid);
    int (*set_active_group)(struct fingerprint_device* dev, uint32_t gid, const char* store_path);
    int (*authenticate)(struct fingerprint_device* dev, uint64_t operation_id, uint32_t gid);
    int (*extCmd)(struct fingerprint_device* dev, int32_t cmd, int32_t param);
} fingerprint_device_t;

static_assert(offsetof(fingerprint_device_t, common.close) == 0x70, "close must be at 0x70");
static_assert(offsetof(fingerprint_device_t, set_notify) == 0x80, "set_notify must be at 0x80");
static_assert(offsetof(fingerprint_device_t, authenticate) == 0xc8, "authenticate must be at 0xc8");
static_assert(offsetof(fingerprint_device_t, extCmd) == 0xd0, "extCmd must be at 0xd0");

// ============================================================================
// Xiaomi Display Feature & Touch Feature Kernel IOCTLs
// Verified from libmifpext.so & vendor.xiaomi.hardware.touchfeature@1.0-impl.so
// ============================================================================

static constexpr unsigned long MI_DISP_IOCTL_REGISTER_EVENT = 0x400c4407UL;
static constexpr unsigned long MI_DISP_IOCTL_SET_LOCAL_HBM  = 0x400c440eUL;
static constexpr uint32_t MI_DISP_EVENT_FOD = 2;

// Local HBM modes on Xiaomi panel_o7_38_0c_0a_dsc_vdo (verified in kernel dmesg & libmifpext.so):
//   0 = OFF, 2 = LOCAL_HBM_NORMAL_WHITE_1200NIT (screen-on & screen-off), 3 = WHITE_200NIT,
//   4 = LHBM_ON_GREEN_500NIT (factory/test green light - DO NOT USE for FOD!).
static constexpr int32_t kLocalHbmOff = 0;
static constexpr int32_t kLocalHbmNormalWhite = 2;

struct mi_disp_local_hbm_req {
    uint32_t flag;     // 1
    int32_t disp_id;   // 0 (primary)
    int32_t value;     // 0 = OFF, 2 = LOCAL_HBM_NORMAL_WHITE_1200NIT
};
static_assert(sizeof(mi_disp_local_hbm_req) == 12, "mi_disp_local_hbm_req must be 12 bytes");

struct mi_disp_event_req {
    uint32_t flag;     // 0
    int32_t disp_id;   // 0
    uint32_t type;     // 2 (MI_DISP_EVENT_FOD)
};
static_assert(sizeof(mi_disp_event_req) == 12, "mi_disp_event_req must be 12 bytes");

struct mi_disp_event_resp {
    int32_t disp_id;
    uint32_t type;
    uint32_t length;
    int32_t data;      // 0x8 when LHBM active, 0x0 when off
};

// /dev/xiaomi-touch ioctl (verified from TouchFeature::setModeValue)
static constexpr unsigned long TOUCH_IOC_SET_CUR_VALUE = 0x5400UL;
static constexpr int32_t TOUCH_MODE_FOD_ENABLE = 10;

// Xiaomi FOD input key (fts_ts emits BTN_INFO=0x152 on FOD press)
#ifndef BTN_INFO
#define BTN_INFO 0x152
#endif

// ============================================================================
// AIDL V3 Fingerprint & ColorOS 17 Extension Constants
// Verified from oplus-services.jar FingerprintServiceProviderExtImpl
// ============================================================================

static constexpr const char* kIFingerprintDescriptor =
        "android.hardware.biometrics.fingerprint.IFingerprint";
static constexpr const char* kIFingerprintInstance =
        "android.hardware.biometrics.fingerprint.IFingerprint/default";
static constexpr const char* kISessionDescriptor =
        "android.hardware.biometrics.fingerprint.ISession";
static constexpr const char* kISessionCallbackDescriptor =
        "android.hardware.biometrics.fingerprint.ISessionCallback";
static constexpr const char* kICancellationSignalDescriptor =
        "android.hardware.biometrics.common.ICancellationSignal";

static constexpr int32_t kAidlFpVersion = 3;
static constexpr const char* kAidlFpHash = "637371b53fb7faf9bd43aa51b72c23852d6e6d96";
static constexpr int32_t kAidlCommonVersion = 3;
static constexpr const char* kAidlCommonHash = "a9ebb97f5abea1dc6800b69d821ef61944e80e65";

static constexpr transaction_code_t kTxGetInterfaceVersion = 16777215;  // 0xffffff
static constexpr transaction_code_t kTxGetInterfaceHash = 16777214;     // 0xfffffe
static constexpr transaction_code_t kOplusTxSendFpCmd = 1019;           // 0x3fb

// ColorOS ISessionCallback custom transaction (FingerprintServiceProviderExtImpl::onTransactFromHal):
//   tx 1001 = onFingerprintCmd(int32 cmdId, int32 len, byte[] result)
//   cmdId 1201 = dispatchTouchDown() (8-byte LE uptimeMillis -> plays pressed anim & wakes screen-off)
//   cmdId 1202 = dispatchTouchUp()   (stops pressed anim & unblocks)
static constexpr transaction_code_t kOplusCbTxOnFingerprintCmd = 1001;
static constexpr int32_t kOplusCmdTouchDown = 1201;
static constexpr int32_t kOplusCmdTouchUp = 1202;

// ColorOS inbound sendFingerprintCmd(1019) command IDs
static constexpr int32_t kOplusInCmdGetEnrollTotalTimes = 1010;  // return -1 -> dynamic remaining + 1
static constexpr int32_t kOplusInCmdScreenState = 1011;          // firstVal: 0=screen OFF, 1=screen ON

// Xiaomi extCmd codes (verified from fingerprint.jiiov.so & libmifpext.so)
static constexpr int32_t kXiaomiCmdFingerTouch = 1;  // param: 1=down (Anc 13), 0=up (Anc 14)
static constexpr int32_t kXiaomiCmdTouchX = 2;       // param: touch X px
static constexpr int32_t kXiaomiCmdTouchY = 3;       // param: touch Y px
static constexpr int32_t kXiaomiCmdUiReady = 10;     // param: 1=HBM ready (Anc 100001), 0=HBM off (Anc 71)

// Dynamic FOD sensor geometry (loaded from props at startup, defaults for tanzanite)
static int32_t gFodCenterX = 540;
static int32_t gFodCenterY = 2109;
static int32_t gFodRadius = 93;
static int32_t gDisplayWidth = 1080;
static int32_t gDisplayHeight = 2400;

static int64_t getUptimeMillis() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000LL + ts.tv_nsec / 1000000LL;
}

static void loadFodGeometryFromProps() {
    char locBuf[PROP_VALUE_MAX] = {0};
    char sizeBuf[PROP_VALUE_MAX] = {0};

    int locLen = __system_property_get("persist.vendor.sys.fp.fod.location.X_Y", locBuf);
    int sizeLen = __system_property_get("persist.vendor.sys.fp.fod.size.width_height", sizeBuf);

    int x = 0, y = 0, w = 186, h = 186;
    if (sizeLen > 0 && sscanf(sizeBuf, "%d,%d", &w, &h) == 2 && w > 0 && h > 0) {
        gFodRadius = (w > h ? w : h) / 2;
    } else if (__system_property_get("persist.vendor.fingerprint.optical.iconsize", sizeBuf) > 0) {
        int sz = atoi(sizeBuf);
        if (sz > 0) {
            w = h = sz;
            gFodRadius = sz / 2;
        }
    }

    if (locLen > 0 && sscanf(locBuf, "%d,%d", &x, &y) == 2 && x > 0 && y > 0) {
        gFodCenterX = x + w / 2;
        gFodCenterY = y + h / 2;
    } else if (__system_property_get("persist.vendor.fingerprint.optical.sensorlocation", locBuf) > 0 &&
               sscanf(locBuf, "%d,%d", &x, &y) == 2 && x > 0 && y > 0) {
        gFodCenterX = x;
        gFodCenterY = y;
    }

    ALOGI("Loaded FOD geometry: center=(%d,%d) radius=%d screen=(%dx%d)",
          gFodCenterX, gFodCenterY, gFodRadius, gDisplayWidth, gDisplayHeight);
}

// ============================================================================
// Parcel helpers for Stable AIDL wire format
// ============================================================================

struct ParcelableWriter {
    AParcel* p;
    int32_t startPos;
    explicit ParcelableWriter(AParcel* parcel, bool writeNonNull = true) : p(parcel) {
        if (writeNonNull) {
            AParcel_writeInt32(p, 1);
        }
        startPos = AParcel_getDataPosition(p);
        AParcel_writeInt32(p, 0);
    }
    void finish() {
        int32_t endPos = AParcel_getDataPosition(p);
        AParcel_setDataPosition(p, startPos);
        AParcel_writeInt32(p, endPos - startPos);
        AParcel_setDataPosition(p, endPos);
    }
};

static void writeOkStatus(AParcel* out) {
    AStatus* st = AStatus_newOk();
    AParcel_writeStatusHeader(out, st);
    AStatus_delete(st);
}

static bool readByteArrayVec(const AParcel* in, std::vector<uint8_t>& out) {
    auto alloc = [](void* vecPtr, int32_t len, int8_t** outBuf) -> bool {
        auto* vec = static_cast<std::vector<uint8_t>*>(vecPtr);
        if (len < 0) {
            vec->clear();
            *outBuf = nullptr;
            return true;
        }
        vec->resize(static_cast<size_t>(len));
        *outBuf = reinterpret_cast<int8_t*>(vec->data());
        return true;
    };
    return AParcel_readByteArray(in, &out, alloc) == STATUS_OK;
}

static bool readInt32ArrayVec(const AParcel* in, std::vector<int32_t>& out) {
    auto alloc = [](void* vecPtr, int32_t len, int32_t** outBuf) -> bool {
        auto* vec = static_cast<std::vector<int32_t>*>(vecPtr);
        if (len < 0) {
            vec->clear();
            *outBuf = nullptr;
            return true;
        }
        vec->resize(static_cast<size_t>(len));
        *outBuf = vec->data();
        return true;
    };
    return AParcel_readInt32Array(in, &out, alloc) == STATUS_OK;
}

static bool skipParcelable(const AParcel* in) {
    int32_t nonNull = 0;
    if (AParcel_readInt32(in, &nonNull) != STATUS_OK) return false;
    if (nonNull == 0) return true;
    int32_t startPos = AParcel_getDataPosition(in);
    int32_t size = 0;
    if (AParcel_readInt32(in, &size) != STATUS_OK || size < 4) return false;
    return AParcel_setDataPosition(in, startPos + size) == STATUS_OK;
}

static bool readHardwareAuthToken(const AParcel* in, hw_auth_token_t& legacyHat) {
    memset(&legacyHat, 0, sizeof(legacyHat));
    int32_t nonNull = 0;
    if (AParcel_readInt32(in, &nonNull) != STATUS_OK) return false;
    if (nonNull == 0) return true;

    int32_t startPos = AParcel_getDataPosition(in);
    int32_t size = 0;
    if (AParcel_readInt32(in, &size) != STATUS_OK || size < 4) return false;

    int64_t challenge = 0, userId = 0, authenticatorId = 0;
    int32_t authenticatorType = 0;
    int64_t tsMillis = 0;
    std::vector<uint8_t> mac;

    AParcel_readInt64(in, &challenge);
    AParcel_readInt64(in, &userId);
    AParcel_readInt64(in, &authenticatorId);
    AParcel_readInt32(in, &authenticatorType);

    int32_t tsNonNull = 0;
    if (AParcel_readInt32(in, &tsNonNull) == STATUS_OK && tsNonNull != 0) {
        int32_t tsStart = AParcel_getDataPosition(in);
        int32_t tsSize = 0;
        if (AParcel_readInt32(in, &tsSize) == STATUS_OK && tsSize >= 4) {
            AParcel_readInt64(in, &tsMillis);
            AParcel_setDataPosition(in, tsStart + tsSize);
        }
    }

    readByteArrayVec(in, mac);
    AParcel_setDataPosition(in, startPos + size);

    legacyHat.version = 0;
    legacyHat.challenge = static_cast<uint64_t>(challenge);
    legacyHat.user_id = static_cast<uint64_t>(userId);
    legacyHat.authenticator_id = static_cast<uint64_t>(authenticatorId);
    legacyHat.authenticator_type = htonl(static_cast<uint32_t>(authenticatorType));
    legacyHat.timestamp = htobe64(static_cast<uint64_t>(tsMillis));
    if (!mac.empty()) {
        size_t copyLen = mac.size() < 32 ? mac.size() : 32;
        memcpy(legacyHat.hmac, mac.data(), copyLen);
    }
    return true;
}

static void writeHardwareAuthToken(AParcel* out, const hw_auth_token_t& legacyHat) {
    ParcelableWriter hatPw(out, true);
    AParcel_writeInt64(out, static_cast<int64_t>(legacyHat.challenge));
    AParcel_writeInt64(out, static_cast<int64_t>(legacyHat.user_id));
    AParcel_writeInt64(out, static_cast<int64_t>(legacyHat.authenticator_id));
    AParcel_writeInt32(out, static_cast<int32_t>(ntohl(legacyHat.authenticator_type)));
    {
        ParcelableWriter tsPw(out, true);
        AParcel_writeInt64(out, static_cast<int64_t>(be64toh(legacyHat.timestamp)));
        tsPw.finish();
    }
    AParcel_writeByteArray(out, reinterpret_cast<const int8_t*>(legacyHat.hmac), 32);
    hatPw.finish();
}

// ============================================================================
// Global HAL + Session + FOD Hardware State
// ============================================================================

namespace {

static fingerprint_device_t* gFpDevice = nullptr;
static std::string gSensorVendor = "jiiov";

// Display / LHBM state
static int gDispFeatureFd = -1;
static std::mutex gDispMutex;
static std::atomic<bool> gHbmActive{false};
static std::atomic<bool> gScreenOn{true};

// Active operation & finger press state
static std::atomic<bool> gOpActive{false};
static std::atomic<bool> gTouchFodEnabled{false};
static std::atomic<bool> gOplusTouchDownSent{false};
static std::mutex gFingerMutex;
static bool gFingerDown = false;
static bool gUiReadySent = false;
static uint64_t gPressSeq = 0;

// Ordered asynchronous ISessionCallback dispatcher (prevents synchronous re-entrant
// callbacks from firing before ISession::onTransact returns writeOkStatus to system_server).
static std::mutex gCbQueueMutex;
static std::condition_variable gCbQueueCv;
static std::deque<std::function<void()>> gCbQueue;
static std::atomic<bool> gCbWorkerStarted{false};

static void cbWorkerLoop() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lk(gCbQueueMutex);
            gCbQueueCv.wait(lk, []() { return !gCbQueue.empty(); });
            task = std::move(gCbQueue.front());
            gCbQueue.pop_front();
        }
        if (task) {
            task();
        }
    }
}

static void startCallbackWorker() {
    bool expected = false;
    if (gCbWorkerStarted.compare_exchange_strong(expected, true)) {
        std::thread(cbWorkerLoop).detach();
    }
}

static void postCallback(std::function<void()> fn) {
    startCallbackWorker();
    {
        std::lock_guard<std::mutex> lk(gCbQueueMutex);
        gCbQueue.push_back(std::move(fn));
    }
    gCbQueueCv.notify_one();
}

static void flushCallbackQueueForTest() {
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    postCallback([&]() {
        {
            std::lock_guard<std::mutex> lk(m);
            done = true;
        }
        cv.notify_one();
    });
    std::unique_lock<std::mutex> lk(m);
    cv.wait_for(lk, std::chrono::seconds(2), [&]() { return done; });
}

// UI-ready fallback waiter
static std::mutex gUiWaitMutex;
static std::condition_variable gUiWaitCv;
static uint64_t gUiWaitSeq = 0;
static int32_t gUiWaitTimeoutMs = 80;

struct SessionState {
    int32_t sensorId = 0;
    int32_t userId = 0;
    AIBinder* callback = nullptr;
    bool closed = false;
};

static std::mutex gSessionMutex;
static SessionState* gActiveSession = nullptr;
static std::vector<int32_t> gEnumIds;
static std::vector<int32_t> gRemovedIds;

static AIBinder* acquireActiveCallback() {
    std::lock_guard<std::mutex> lock(gSessionMutex);
    if (gActiveSession && !gActiveSession->closed && gActiveSession->callback) {
        AIBinder_incStrong(gActiveSession->callback);
        return gActiveSession->callback;
    }
    return nullptr;
}

// Forward declarations for callback helpers used by FOD touch/display threads
static void cbOnFingerprintCmd(AIBinder* cb, int32_t cmdId, const uint8_t* data, int32_t len);

// ============================================================================
// Xiaomi Hardware Controls: /dev/xiaomi-touch + /dev/mi_display/disp_feature
// ============================================================================

static void setTouchFodMode(bool enable) {
    bool expected = !enable;
    if (!gTouchFodEnabled.compare_exchange_strong(expected, enable)) {
        return;
    }
    int fd = open("/dev/xiaomi-touch", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        ALOGW("setTouchFodMode(%d): open(/dev/xiaomi-touch) failed: %s",
              enable ? 1 : 0, strerror(errno));
        return;
    }
    int32_t buf[4] = {TOUCH_MODE_FOD_ENABLE, enable ? 1 : 0, 0, 0};
    int ret = ioctl(fd, TOUCH_IOC_SET_CUR_VALUE, buf);
    close(fd);
    if (ret != 0) {
        ALOGW("setTouchFodMode(%d): ioctl(0x5400, {10,%d}) failed: ret=%d errno=%d (%s)",
              enable ? 1 : 0, enable ? 1 : 0, ret, errno, strerror(errno));
    } else {
        ALOGI("setTouchFodMode(%d): /dev/xiaomi-touch Touch_Fod_Enable=%d OK",
              enable ? 1 : 0, enable ? 1 : 0);
    }
}

static void setLocalHbm(bool enable) {
    bool expected = !enable;
    if (!gHbmActive.compare_exchange_strong(expected, enable)) {
        return;
    }

    std::lock_guard<std::mutex> lock(gDispMutex);
    if (gDispFeatureFd < 0) {
        gDispFeatureFd = open("/dev/mi_display/disp_feature", O_RDWR | O_CLOEXEC);
        if (gDispFeatureFd < 0) {
            gDispFeatureFd = open("/dev/disp_feature", O_RDWR | O_CLOEXEC);
        }
        if (gDispFeatureFd < 0) {
            ALOGW("Could not open /dev/mi_display/disp_feature: %s", strerror(errno));
        }
    }
    if (gDispFeatureFd >= 0) {
        mi_disp_local_hbm_req req{};
        req.flag = 1;
        req.disp_id = 0;
        bool screenOn = gScreenOn.load();
        // Always use LOCAL_HBM_NORMAL_WHITE_1200NIT (2) for both screen-on and screen-off FOD;
        // mode 4 is green 500nit (factory test) and prevents the optical sensor from reading.
        req.value = enable ? kLocalHbmNormalWhite : kLocalHbmOff;
        int ret = ioctl(gDispFeatureFd, MI_DISP_IOCTL_SET_LOCAL_HBM, &req);
        if (ret != 0) {
            ALOGW("MI_DISP_IOCTL_SET_LOCAL_HBM(%d) failed: ret=%d errno=%d (%s)",
                  req.value, ret, errno, strerror(errno));
        } else {
            ALOGI("MI_DISP_IOCTL_SET_LOCAL_HBM(%d) OK (screenOn=%d)", req.value, screenOn ? 1 : 0);
        }
    }
}

static void triggerUiReady(const char* source) {
    {
        std::lock_guard<std::mutex> lock(gFingerMutex);
        if (!gFingerDown || gUiReadySent) {
            return;
        }
        gUiReadySent = true;
    }
    gUiWaitCv.notify_all();
    if (gFpDevice && gFpDevice->extCmd) {
        int r = gFpDevice->extCmd(gFpDevice, kXiaomiCmdUiReady, 1);
        ALOGI("FOD UI_READY (%s) -> extCmd(10,1)=%d", source, r);
    }
}

static void sendOplusTouchCmd(bool down) {
    bool expected = !down;
    if (!gOplusTouchDownSent.compare_exchange_strong(expected, down)) {
        return;
    }
    AIBinder* cb = acquireActiveCallback();
    if (!cb) return;
    int64_t ts = down ? getUptimeMillis() : 0;
    postCallback([cb, down, ts]() {
        uint8_t payload[8] = {0};
        if (down) {
            memcpy(payload, &ts, sizeof(ts));  // 8-byte little-endian uptimeMillis
        }
        cbOnFingerprintCmd(cb, down ? kOplusCmdTouchDown : kOplusCmdTouchUp, payload, 8);
        AIBinder_decStrong(cb);
    });
}

static void onFodFingerEvent(bool down, int32_t x, int32_t y, const char* source,
                             bool emitOplusCallback = true) {
    uint64_t seq = 0;
    {
        std::lock_guard<std::mutex> lock(gFingerMutex);
        if (down) {
            if (!gOpActive.load()) {
                return;
            }
            if (gFingerDown) {
                return;
            }
            gFingerDown = true;
            gUiReadySent = false;
            seq = ++gPressSeq;
        } else {
            if (!gFingerDown) {
                return;
            }
            gFingerDown = false;
            gUiReadySent = false;
            ++gPressSeq;
        }
    }

    if (down) {
        bool screenOn = gScreenOn.load();
        ALOGI("FOD DOWN (%s) at (%d,%d) seq=%llu screenOn=%d",
              source, x, y, (unsigned long long)seq, screenOn ? 1 : 0);
        if (emitOplusCallback) {
            // Notify ColorOS FIRST so pressed animation & screen-off wake pipeline start immediately
            sendOplusTouchCmd(true);
        }
        if (gFpDevice && gFpDevice->extCmd) {
            gFpDevice->extCmd(gFpDevice, kXiaomiCmdTouchX, x);
            gFpDevice->extCmd(gFpDevice, kXiaomiCmdTouchY, y);
        }
        setLocalHbm(true);
        if (gFpDevice && gFpDevice->extCmd) {
            int r1 = gFpDevice->extCmd(gFpDevice, kXiaomiCmdFingerTouch, 1);
            ALOGI("FOD DOWN -> extCmd(1,1)=%d", r1);
        }
        // Arm fallback timer (80ms when screen ON, 350ms when screen OFF);
        // DisplayMonitorThread fires immediately as soon as kernel sends MI_DISP_EVENT_FOD != 0.
        {
            std::lock_guard<std::mutex> lk(gUiWaitMutex);
            gUiWaitTimeoutMs = screenOn ? 80 : 350;
            gUiWaitSeq = seq;
        }
        gUiWaitCv.notify_all();
    } else {
        ALOGI("FOD UP (%s)", source);
        gUiWaitCv.notify_all();
        if (gFpDevice && gFpDevice->extCmd) {
            int r1 = gFpDevice->extCmd(gFpDevice, kXiaomiCmdUiReady, 0);
            int r2 = gFpDevice->extCmd(gFpDevice, kXiaomiCmdFingerTouch, 0);
            ALOGI("FOD UP -> extCmd(10,0)=%d extCmd(1,0)=%d", r1, r2);
        }
        setLocalHbm(false);
        if (emitOplusCallback) {
            sendOplusTouchCmd(false);
        }
    }
}

static void endFodOperation(const char* reason) {
    gOpActive.store(false);
    onFodFingerEvent(false, gFodCenterX, gFodCenterY, reason, true);
    setTouchFodMode(false);
}

static void turnOffHbmAfterCapture(const char* reason) {
    ALOGI("FOD turnOffHbmAfterCapture(%s)", reason);
    if (gFpDevice && gFpDevice->extCmd) {
        gFpDevice->extCmd(gFpDevice, kXiaomiCmdUiReady, 0);
    }
    setLocalHbm(false);
    // Dismiss ColorOS pressed icon immediately after capture so it does not linger
    sendOplusTouchCmd(false);
}

// ============================================================================
// Background Monitor Threads: UI-Ready Fallback, Display LHBM Event, Touch FOD
// ============================================================================

static void uiReadyFallbackLoop() {
    uint64_t lastHandledSeq = 0;
    while (true) {
        uint64_t targetSeq = 0;
        int32_t timeoutMs = 80;
        {
            std::unique_lock<std::mutex> lk(gUiWaitMutex);
            gUiWaitCv.wait(lk, [&]() { return gUiWaitSeq != lastHandledSeq; });
            targetSeq = gUiWaitSeq;
            timeoutMs = gUiWaitTimeoutMs;
            lastHandledSeq = targetSeq;
        }
        std::unique_lock<std::mutex> lk(gUiWaitMutex);
        gUiWaitCv.wait_for(lk, std::chrono::milliseconds(timeoutMs), [&]() {
            std::lock_guard<std::mutex> flk(gFingerMutex);
            return !gFingerDown || gUiReadySent || gPressSeq != targetSeq;
        });
        lk.unlock();

        bool shouldFire = false;
        {
            std::lock_guard<std::mutex> flk(gFingerMutex);
            if (gFingerDown && !gUiReadySent && gPressSeq == targetSeq) {
                shouldFire = true;
            }
        }
        if (shouldFire) {
            char tag[32];
            snprintf(tag, sizeof(tag), "fallback-%dms", timeoutMs);
            triggerUiReady(tag);
        }
    }
}

static void displayMonitorLoop() {
    int fd = open("/dev/mi_display/disp_feature", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fd = open("/dev/disp_feature", O_RDWR | O_CLOEXEC);
    }
    if (fd < 0) {
        ALOGW("DisplayMonitorThread: failed to open disp_feature: %s (using fallback timer)",
              strerror(errno));
        return;
    }

    mi_disp_event_req evReq{};
    evReq.flag = 0;
    evReq.disp_id = 0;
    evReq.type = MI_DISP_EVENT_FOD;
    int ret = ioctl(fd, MI_DISP_IOCTL_REGISTER_EVENT, &evReq);
    if (ret != 0) {
        ALOGW("DisplayMonitorThread: REGISTER_EVENT(FOD) failed: ret=%d errno=%d (%s)",
              ret, errno, strerror(errno));
        close(fd);
        return;
    }
    ALOGI("DisplayMonitorThread: registered MI_DISP_EVENT_FOD (fd=%d)", fd);

    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN | POLLPRI | POLLERR | POLLRDNORM;

    uint8_t buf[64];
    while (true) {
        pfd.revents = 0;
        int pr = poll(&pfd, 1, -1);
        if (pr <= 0) {
            if (errno == EINTR) continue;
            usleep(10000);
            continue;
        }
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n >= static_cast<ssize_t>(sizeof(mi_disp_event_resp))) {
            mi_disp_event_resp resp{};
            memcpy(&resp, buf, sizeof(resp));
            ALOGI("DisplayMonitorThread: event disp=%d type=%u len=%u data=0x%x",
                  resp.disp_id, resp.type, resp.length, resp.data);
            // Xiaomi MTK/mi_disp emits data=0x8 (non-zero) when Local HBM is active, 0x0 when off
            if (resp.type == MI_DISP_EVENT_FOD && resp.data != 0) {
                triggerUiReady("MI_DISP_EVENT_FOD");
            }
        }
    }
}

static int findTouchInputDevice(int32_t& absMaxX, int32_t& absMaxY) {
    char path[64];
    for (int i = 0; i < 16; ++i) {
        snprintf(path, sizeof(path), "/dev/input/event%d", i);
        int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) continue;

        unsigned long evBits[(EV_MAX / (sizeof(unsigned long) * 8)) + 1] = {0};
        unsigned long absBits[(ABS_MAX / (sizeof(unsigned long) * 8)) + 1] = {0};
        if (ioctl(fd, EVIOCGBIT(0, sizeof(evBits)), evBits) < 0) {
            close(fd);
            continue;
        }
        bool hasAbs = (evBits[EV_ABS / (sizeof(unsigned long) * 8)] &
                       (1UL << (EV_ABS % (sizeof(unsigned long) * 8)))) != 0;
        if (!hasAbs || ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(absBits)), absBits) < 0) {
            close(fd);
            continue;
        }
        auto testBit = [](const unsigned long* arr, int bit) {
            return (arr[bit / (sizeof(unsigned long) * 8)] &
                    (1UL << (bit % (sizeof(unsigned long) * 8)))) != 0;
        };
        if (testBit(absBits, ABS_MT_POSITION_X) && testBit(absBits, ABS_MT_POSITION_Y)) {
            input_absinfo ax{}, ay{};
            ioctl(fd, EVIOCGABS(ABS_MT_POSITION_X), &ax);
            ioctl(fd, EVIOCGABS(ABS_MT_POSITION_Y), &ay);
            char name[128] = {0};
            ioctl(fd, EVIOCGNAME(sizeof(name) - 1), name);
            absMaxX = ax.maximum > 0 ? ax.maximum : gDisplayWidth;
            absMaxY = ay.maximum > 0 ? ay.maximum : gDisplayHeight;
            ALOGI("TouchMonitorThread: opened touch input %s (%s) absMax=(%d,%d)",
                  path, name, absMaxX, absMaxY);
            return fd;
        }
        close(fd);
    }
    return -1;
}

static void touchMonitorLoop() {
    static constexpr const char* kFodStatusPath = "/sys/class/touch/touch_dev/fod_press_status";
    int fodStatusFd = open(kFodStatusPath, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fodStatusFd >= 0) {
        char dummy[16] = {0};
        ssize_t n = pread(fodStatusFd, dummy, sizeof(dummy) - 1, 0);
        ALOGI("TouchMonitorThread: opened %s (fd=%d, init='%.*s')",
              kFodStatusPath, fodStatusFd, (int)(n > 0 ? n : 0), dummy);
    } else {
        ALOGW("TouchMonitorThread: failed to open %s: %s", kFodStatusPath, strerror(errno));
    }

    int32_t absMaxX = gDisplayWidth;
    int32_t absMaxY = gDisplayHeight;
    int inputFd = findTouchInputDevice(absMaxX, absMaxY);
    if (inputFd < 0) {
        ALOGW("TouchMonitorThread: could not open any multitouch /dev/input/event*");
    }

    if (fodStatusFd < 0 && inputFd < 0) {
        ALOGE("TouchMonitorThread: NO touch input source available!");
        return;
    }

    int32_t curSlot = 0;
    int32_t slotId[10];
    int32_t slotX[10];
    int32_t slotY[10];
    for (int i = 0; i < 10; ++i) {
        slotId[i] = -1;
        slotX[i] = gFodCenterX;
        slotY[i] = gFodCenterY;
    }
    int32_t lastTouchX = gFodCenterX;
    int32_t lastTouchY = gFodCenterY;
    bool inputHitActive = false;
    bool fodStatusDown = false;
    bool btnInfoDown = false;
    const int64_t hitRadius = (gFodRadius * 3 / 2 > 130) ? (gFodRadius * 3 / 2) : 130;
    const int64_t hitRadiusSq = hitRadius * hitRadius;

    pollfd pfds[2];
    while (true) {
        int nfds = 0;
        int idxFod = -1, idxInp = -1;
        if (fodStatusFd >= 0) {
            idxFod = nfds++;
            pfds[idxFod].fd = fodStatusFd;
            pfds[idxFod].events = POLLPRI | POLLERR;
            pfds[idxFod].revents = 0;
        }
        if (inputFd >= 0) {
            idxInp = nfds++;
            pfds[idxInp].fd = inputFd;
            pfds[idxInp].events = POLLIN;
            pfds[idxInp].revents = 0;
        }

        int pr = poll(pfds, nfds, -1);
        if (pr <= 0) {
            if (errno == EINTR) continue;
            usleep(10000);
            continue;
        }

        // 1. Primary Xiaomi sysfs fod_press_status
        if (idxFod >= 0 && (pfds[idxFod].revents & (POLLPRI | POLLERR))) {
            char buf[16] = {0};
            ssize_t n = pread(fodStatusFd, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                bool down = (buf[0] == '1');
                if (down != fodStatusDown) {
                    fodStatusDown = down;
                    ALOGI("TouchMonitorThread: fod_press_status -> '%c' (opActive=%d btn=%d)",
                          buf[0], gOpActive.load() ? 1 : 0, btnInfoDown ? 1 : 0);
                    if (down || !btnInfoDown) {
                        onFodFingerEvent(down, lastTouchX, lastTouchY, "fod_press_status");
                    }
                }
            }
        }

        // 2. Touchscreen /dev/input/event* (coordinates + BTN_INFO + hit-test fallback if no sysfs)
        if (idxInp >= 0 && (pfds[idxInp].revents & POLLIN)) {
            input_event evs[32];
            ssize_t nbytes = read(inputFd, evs, sizeof(evs));
            int count = static_cast<int>(nbytes / sizeof(input_event));
            for (int i = 0; i < count; ++i) {
                const input_event& ev = evs[i];
                if (ev.type == EV_KEY && ev.code == BTN_INFO) {
                    bool down = (ev.value != 0);
                    btnInfoDown = down;
                    ALOGI("TouchMonitorThread: BTN_INFO=%d (opActive=%d fodStatus=%d)",
                          ev.value, gOpActive.load() ? 1 : 0, fodStatusDown ? 1 : 0);
                    if (down || !fodStatusDown) {
                        onFodFingerEvent(down, lastTouchX, lastTouchY, "BTN_INFO");
                    }
                } else if (ev.type == EV_ABS) {
                    if (ev.code == ABS_MT_SLOT) {
                        curSlot = (ev.value >= 0 && ev.value < 10) ? ev.value : 0;
                    } else if (ev.code == ABS_MT_TRACKING_ID) {
                        slotId[curSlot] = ev.value;
                    } else if (ev.code == ABS_MT_POSITION_X) {
                        int32_t px = static_cast<int32_t>(
                                (static_cast<int64_t>(ev.value) * gDisplayWidth) / absMaxX);
                        slotX[curSlot] = px;
                        lastTouchX = px;
                    } else if (ev.code == ABS_MT_POSITION_Y) {
                        int32_t py = static_cast<int32_t>(
                                (static_cast<int64_t>(ev.value) * gDisplayHeight) / absMaxY);
                        slotY[curSlot] = py;
                        lastTouchY = py;
                    }
                } else if (ev.type == EV_SYN && ev.code == SYN_REPORT) {
                    // Only use multitouch coordinate hit-testing as press trigger if fod_press_status
                    // is unavailable; otherwise fod_press_status + BTN_INFO provide clean hardware FOD events.
                    if (fodStatusFd < 0) {
                        bool anyInFod = false;
                        int32_t hitX = gFodCenterX;
                        int32_t hitY = gFodCenterY;
                        for (int s = 0; s < 10; ++s) {
                            if (slotId[s] >= 0) {
                                int64_t dx = slotX[s] - gFodCenterX;
                                int64_t dy = slotY[s] - gFodCenterY;
                                if (dx * dx + dy * dy <= hitRadiusSq) {
                                    anyInFod = true;
                                    hitX = slotX[s];
                                    hitY = slotY[s];
                                    break;
                                }
                            }
                        }
                        if (anyInFod && !inputHitActive) {
                            inputHitActive = true;
                            if (gOpActive.load()) {
                                onFodFingerEvent(true, hitX, hitY, "input_mt");
                            }
                        } else if (!anyInFod && inputHitActive) {
                            inputHitActive = false;
                            if (!btnInfoDown) {
                                onFodFingerEvent(false, lastTouchX, lastTouchY, "input_mt");
                            }
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// ISessionCallback Outbound Helpers (tx 1..16 + ColorOS tx 1001)
// ============================================================================

template <typename WriteFn>
static void sendCallback(AIBinder* cb, transaction_code_t tx, WriteFn writeArgs) {
    if (!cb) return;
    AParcel* in = nullptr;
    AParcel* out = nullptr;
    binder_status_t st = AIBinder_prepareTransaction(cb, &in);
    if (st != STATUS_OK) {
        ALOGE("sendCallback(tx=%u): prepareTransaction failed: %d", tx, st);
        return;
    }
    writeArgs(in);
    st = AIBinder_transact(cb, tx, &in, &out, 0);
    if (st != STATUS_OK) {
        ALOGW("sendCallback(tx=%u): transact failed: %d", tx, st);
    }
    if (out) {
        AStatus* rstat = nullptr;
        if (AParcel_readStatusHeader(out, &rstat) == STATUS_OK && rstat) {
            if (!AStatus_isOk(rstat)) {
                ALOGW("sendCallback(tx=%u): remote exception code=%d msg=%s",
                      tx, AStatus_getExceptionCode(rstat), AStatus_getMessage(rstat));
            }
            AStatus_delete(rstat);
        }
        AParcel_delete(out);
    }
}

static void cbOnChallengeGenerated(AIBinder* cb, int64_t challenge) {
    sendCallback(cb, 1, [&](AParcel* in) { AParcel_writeInt64(in, challenge); });
}

static void cbOnChallengeRevoked(AIBinder* cb, int64_t challenge) {
    sendCallback(cb, 2, [&](AParcel* in) { AParcel_writeInt64(in, challenge); });
}

static void cbOnAcquired(AIBinder* cb, int8_t info, int32_t vendorCode) {
    sendCallback(cb, 3, [&](AParcel* in) {
        AParcel_writeByte(in, info);
        AParcel_writeInt32(in, vendorCode);
    });
}

static void cbOnError(AIBinder* cb, int8_t error, int32_t vendorCode) {
    sendCallback(cb, 4, [&](AParcel* in) {
        AParcel_writeByte(in, error);
        AParcel_writeInt32(in, vendorCode);
    });
}

static void cbOnEnrollmentProgress(AIBinder* cb, int32_t enrollmentId, int32_t remaining) {
    sendCallback(cb, 5, [&](AParcel* in) {
        AParcel_writeInt32(in, enrollmentId);
        AParcel_writeInt32(in, remaining);
    });
}

static void cbOnAuthenticationSucceeded(AIBinder* cb, int32_t enrollmentId,
                                        const hw_auth_token_t& hat) {
    sendCallback(cb, 6, [&](AParcel* in) {
        AParcel_writeInt32(in, enrollmentId);
        writeHardwareAuthToken(in, hat);
    });
}

static void cbOnAuthenticationFailed(AIBinder* cb) {
    sendCallback(cb, 7, [](AParcel*) {});
}

static void cbOnLockoutCleared(AIBinder* cb) {
    sendCallback(cb, 10, [](AParcel*) {});
}

static void cbOnEnrollmentsEnumerated(AIBinder* cb, const std::vector<int32_t>& ids) {
    sendCallback(cb, 12, [&](AParcel* in) {
        AParcel_writeInt32Array(in, ids.empty() ? nullptr : ids.data(),
                                static_cast<int32_t>(ids.size()));
    });
}

static void cbOnEnrollmentsRemoved(AIBinder* cb, const std::vector<int32_t>& ids) {
    sendCallback(cb, 13, [&](AParcel* in) {
        AParcel_writeInt32Array(in, ids.empty() ? nullptr : ids.data(),
                                static_cast<int32_t>(ids.size()));
    });
}

static void cbOnAuthenticatorIdRetrieved(AIBinder* cb, int64_t authenticatorId) {
    sendCallback(cb, 14, [&](AParcel* in) { AParcel_writeInt64(in, authenticatorId); });
}

static void cbOnAuthenticatorIdInvalidated(AIBinder* cb, int64_t newAuthenticatorId) {
    sendCallback(cb, 15, [&](AParcel* in) { AParcel_writeInt64(in, newAuthenticatorId); });
}

static void cbOnSessionClosed(AIBinder* cb) {
    sendCallback(cb, 16, [](AParcel*) {});
}

// ColorOS 17 custom ISessionCallback transaction 1001:
//   FingerprintServiceProviderExtImpl::onTransactFromHal -> onFingerprintCmd(cmdId, len, byte[])
static void cbOnFingerprintCmd(AIBinder* cb, int32_t cmdId, const uint8_t* data, int32_t len) {
    ALOGI("Oplus ISessionCallback::onFingerprintCmd(tx=1001, cmdId=%d, len=%d)", cmdId, len);
    sendCallback(cb, kOplusCbTxOnFingerprintCmd, [&](AParcel* in) {
        AParcel_writeInt32(in, cmdId);
        AParcel_writeInt32(in, len);
        AParcel_writeByteArray(in, reinterpret_cast<const int8_t*>(data), len);
    });
}

// ============================================================================
// Legacy HAL Callback -> AIDL ISessionCallback Translation
// ============================================================================

static void mapLegacyError(int32_t legacyErr, int8_t& aidlErr, int32_t& vendorCode) {
    vendorCode = 0;
    if (legacyErr >= 1000) {
        aidlErr = 7;  // Error::VENDOR
        vendorCode = legacyErr - 1000;
        return;
    }
    switch (legacyErr) {
        case 1: aidlErr = 1; break;  // HW_UNAVAILABLE
        case 2: aidlErr = 2; break;  // UNABLE_TO_PROCESS
        case 3: aidlErr = 3; break;  // TIMEOUT
        case 4: aidlErr = 4; break;  // NO_SPACE
        case 5: aidlErr = 5; break;  // CANCELED
        case 6: aidlErr = 6; break;  // UNABLE_TO_REMOVE
        default: aidlErr = 0; break; // UNKNOWN
    }
}

static void mapLegacyAcquired(int32_t legacyAcq, int8_t& aidlAcq, int32_t& vendorCode) {
    vendorCode = 0;
    if (legacyAcq >= 1000) {
        aidlAcq = 7;  // AcquiredInfo::VENDOR
        vendorCode = legacyAcq - 1000;
        return;
    }
    switch (legacyAcq) {
        case 0: aidlAcq = 1; break;  // GOOD
        case 1: aidlAcq = 2; break;  // PARTIAL
        case 2: aidlAcq = 3; break;  // INSUFFICIENT
        case 3: aidlAcq = 4; break;  // SENSOR_DIRTY
        case 4: aidlAcq = 5; break;  // TOO_SLOW
        case 5: aidlAcq = 6; break;  // TOO_FAST
        default: aidlAcq = 0; break; // UNKNOWN
    }
}

static void halNotifyCallback(const fingerprint_msg_t* msg) {
    if (!msg) return;
    if (static_cast<int32_t>(msg->type) == 7) {
        // Xiaomi proprietary jiiov internal frame notification (not a standard fingerprint_msg_type)
        return;
    }
    AIBinder* cb = acquireActiveCallback();
    if (!cb) {
        ALOGW("halNotifyCallback(type=%d): no active session callback", msg->type);
        return;
    }

    switch (msg->type) {
        case FINGERPRINT_ERROR: {
            int8_t err = 0;
            int32_t vcode = 0;
            mapLegacyError(msg->data.error, err, vcode);
            ALOGI("HAL -> onError(legacy=%d -> aidl=%d, vendor=%d)", msg->data.error, err, vcode);
            endFodOperation("hal-error");
            postCallback([cb, err, vcode]() {
                cbOnError(cb, err, vcode);
                AIBinder_decStrong(cb);
            });
            return;
        }
        case FINGERPRINT_ACQUIRED: {
            int32_t raw = msg->data.acquired.acquired_info;
            // Filter internal jiiov vendor codes (1020 capture-start, 1022 down, 1023 up, 1025 internal)
            if (raw == 1020 || raw == 1022 || raw == 1023 || raw == 1025) {
                break;
            }
            if (raw == 1041) {
                // Dark/low-contrast frame -> translate to standard INSUFFICIENT (3) instead of unknown vendor 41
                ALOGI("HAL -> onAcquired(legacy=1041 -> aidl=3 INSUFFICIENT)");
                postCallback([cb]() {
                    cbOnAcquired(cb, 3, 0);
                    AIBinder_decStrong(cb);
                });
                return;
            }
            int8_t info = 0;
            int32_t vcode = 0;
            mapLegacyAcquired(raw, info, vcode);
            ALOGI("HAL -> onAcquired(legacy=%d -> aidl=%d, vendor=%d)", raw, info, vcode);
            postCallback([cb, info, vcode]() {
                cbOnAcquired(cb, info, vcode);
                AIBinder_decStrong(cb);
            });
            return;
        }
        case FINGERPRINT_TEMPLATE_ENROLLING: {
            int32_t fid = static_cast<int32_t>(msg->data.enroll.finger.fid);
            int32_t rem = static_cast<int32_t>(msg->data.enroll.samples_remaining);
            ALOGI("HAL -> onEnrollmentProgress(fid=%d, remaining=%d)", fid, rem);
            if (rem == 0) {
                endFodOperation("enroll-complete");
            } else {
                // Capture succeeded for this touch; turn off LHBM & pressed icon until next press
                turnOffHbmAfterCapture("enroll-step");
            }
            postCallback([cb, fid, rem]() {
                cbOnEnrollmentProgress(cb, fid, rem);
                AIBinder_decStrong(cb);
            });
            return;
        }
        case FINGERPRINT_TEMPLATE_REMOVED: {
            int32_t fid = static_cast<int32_t>(msg->data.removed.finger.fid);
            uint32_t rem = msg->data.removed.remaining_templates;
            ALOGI("HAL -> removed(fid=%d, remaining=%u)", fid, rem);
            std::vector<int32_t> batch;
            {
                std::lock_guard<std::mutex> lock(gSessionMutex);
                if (fid != 0) gRemovedIds.push_back(fid);
                if (rem == 0) {
                    batch.swap(gRemovedIds);
                }
            }
            if (rem == 0) {
                postCallback([cb, batch = std::move(batch)]() {
                    cbOnEnrollmentsRemoved(cb, batch);
                    AIBinder_decStrong(cb);
                });
                return;
            }
            break;
        }
        case FINGERPRINT_AUTHENTICATED: {
            int32_t fid = static_cast<int32_t>(msg->data.authenticated.finger.fid);
            ALOGI("HAL -> onAuthenticated(fid=%d)", fid);
            if (fid != 0) {
                hw_auth_token_t hatCopy = msg->data.authenticated.hat;
                endFodOperation("auth-success");
                postCallback([cb, fid, hatCopy]() {
                    cbOnAuthenticationSucceeded(cb, fid, hatCopy);
                    AIBinder_decStrong(cb);
                });
                return;
            } else {
                // Keep gOpActive & Touch_Fod_Enable=true for retry, just turn off LHBM & pressed icon
                turnOffHbmAfterCapture("auth-failed");
                postCallback([cb]() {
                    cbOnAuthenticationFailed(cb);
                    AIBinder_decStrong(cb);
                });
                return;
            }
        }
        case FINGERPRINT_TEMPLATE_ENUMERATING: {
            int32_t fid = static_cast<int32_t>(msg->data.enumerated.finger.fid);
            uint32_t rem = msg->data.enumerated.remaining_templates;
            ALOGI("HAL -> enumerated(fid=%d, remaining=%u)", fid, rem);
            std::vector<int32_t> batch;
            {
                std::lock_guard<std::mutex> lock(gSessionMutex);
                if (fid != 0) gEnumIds.push_back(fid);
                if (rem == 0) {
                    batch.swap(gEnumIds);
                }
            }
            if (rem == 0) {
                postCallback([cb, batch = std::move(batch)]() {
                    cbOnEnrollmentsEnumerated(cb, batch);
                    AIBinder_decStrong(cb);
                });
                return;
            }
            break;
        }
        default:
            ALOGW("halNotifyCallback: unknown type=%d", msg->type);
            break;
    }

    AIBinder_decStrong(cb);
}

// ============================================================================
// ICancellationSignal Implementation
// ============================================================================

static AIBinder_Class* gCancelClass = nullptr;

static void* onCreateCancel(void* args) { return args; }
static void onDestroyCancel(void*) {}

static binder_status_t onTransactCancel(
        AIBinder*, transaction_code_t code, const AParcel*, AParcel* out) {
    if (code == 1) {  // cancel()
        ALOGI("ICancellationSignal::cancel()");
        endFodOperation("cancel");
        if (gFpDevice && gFpDevice->cancel) {
            gFpDevice->cancel(gFpDevice);
        }
        return STATUS_OK;  // oneway
    }
    if (code == kTxGetInterfaceVersion) {
        writeOkStatus(out);
        AParcel_writeInt32(out, kAidlCommonVersion);
        return STATUS_OK;
    }
    if (code == kTxGetInterfaceHash) {
        writeOkStatus(out);
        AParcel_writeString(out, kAidlCommonHash, strlen(kAidlCommonHash));
        return STATUS_OK;
    }
    return STATUS_UNKNOWN_TRANSACTION;
}

static AIBinder* createCancellationSignal() {
    if (!gCancelClass) {
        gCancelClass = AIBinder_Class_define(
                kICancellationSignalDescriptor, onCreateCancel, onDestroyCancel, onTransactCancel);
    }
    AIBinder* b = AIBinder_new(gCancelClass, nullptr);
    AIBinder_markVintfStability(b);
    return b;
}

// ============================================================================
// ISession Implementation (AIDL V3, tx 1..22)
// ============================================================================

static AIBinder_Class* gSessionClass = nullptr;

static void* onCreateSession(void* args) { return args; }
static void onDestroySession(void* userData) {
    auto* s = static_cast<SessionState*>(userData);
    if (!s) return;
    {
        std::lock_guard<std::mutex> lock(gSessionMutex);
        if (gActiveSession == s) {
            gActiveSession = nullptr;
        }
    }
    if (s->callback) {
        AIBinder_decStrong(s->callback);
    }
    delete s;
}

static binder_status_t onTransactSession(
        AIBinder* binder, transaction_code_t code, const AParcel* in, AParcel* out) {
    auto* s = static_cast<SessionState*>(AIBinder_getUserData(binder));
    if (!s) return STATUS_BAD_VALUE;

    switch (code) {
        case 1: {  // generateChallenge()
            uint64_t ch = (gFpDevice && gFpDevice->pre_enroll) ? gFpDevice->pre_enroll(gFpDevice) : 0;
            ALOGI("ISession::generateChallenge() -> 0x%llx", (unsigned long long)ch);
            writeOkStatus(out);
            AIBinder* cb = acquireActiveCallback();
            if (cb) {
                postCallback([cb, ch]() {
                    cbOnChallengeGenerated(cb, static_cast<int64_t>(ch));
                    AIBinder_decStrong(cb);
                });
            }
            return STATUS_OK;
        }
        case 2: {  // revokeChallenge(int64 challenge)
            int64_t ch = 0;
            AParcel_readInt64(in, &ch);
            ALOGI("ISession::revokeChallenge(0x%llx)", (unsigned long long)ch);
            if (gFpDevice && gFpDevice->post_enroll) {
                gFpDevice->post_enroll(gFpDevice);
            }
            writeOkStatus(out);
            AIBinder* cb = acquireActiveCallback();
            if (cb) {
                postCallback([cb, ch]() {
                    cbOnChallengeRevoked(cb, ch);
                    AIBinder_decStrong(cb);
                });
            }
            return STATUS_OK;
        }
        case 3:   // enroll(HardwareAuthToken)
        case 16:  // enrollWithContext(HardwareAuthToken, OperationContext)
        {
            hw_auth_token_t hat{};
            readHardwareAuthToken(in, hat);
            if (code == 16) skipParcelable(in);
            ALOGI("ISession::enroll(tx=%u, userId=%d, ch=0x%llx)",
                  code, s->userId, (unsigned long long)hat.challenge);
            int ret = -1;
            if (gFpDevice && gFpDevice->enroll) {
                ret = gFpDevice->enroll(gFpDevice, &hat, static_cast<uint32_t>(s->userId), 60);
            }
            if (ret == 0) {
                gOpActive.store(true);
                setTouchFodMode(true);
            } else {
                ALOGE("HAL enroll() failed: %d", ret);
                endFodOperation("enroll-failed");
                AIBinder* cb = acquireActiveCallback();
                if (cb) {
                    postCallback([cb]() {
                        cbOnError(cb, 2 /* UNABLE_TO_PROCESS */, 0);
                        AIBinder_decStrong(cb);
                    });
                }
            }
            AIBinder* cancelSig = createCancellationSignal();
            writeOkStatus(out);
            AParcel_writeStrongBinder(out, cancelSig);
            AIBinder_decStrong(cancelSig);
            return STATUS_OK;
        }
        case 4:   // authenticate(int64 operationId)
        case 15:  // authenticateWithContext(int64 operationId, OperationContext)
        {
            int64_t opId = 0;
            AParcel_readInt64(in, &opId);
            if (code == 15) skipParcelable(in);
            ALOGI("ISession::authenticate(tx=%u, userId=%d, opId=0x%llx)",
                  code, s->userId, (unsigned long long)opId);
            int ret = -1;
            if (gFpDevice && gFpDevice->authenticate) {
                ret = gFpDevice->authenticate(gFpDevice, static_cast<uint64_t>(opId),
                                              static_cast<uint32_t>(s->userId));
            }
            if (ret == 0) {
                gOpActive.store(true);
                setTouchFodMode(true);
            } else {
                ALOGE("HAL authenticate() failed: %d", ret);
                endFodOperation("auth-start-failed");
                AIBinder* cb = acquireActiveCallback();
                if (cb) {
                    postCallback([cb]() {
                        cbOnError(cb, 2 /* UNABLE_TO_PROCESS */, 0);
                        AIBinder_decStrong(cb);
                    });
                }
            }
            AIBinder* cancelSig = createCancellationSignal();
            writeOkStatus(out);
            AParcel_writeStrongBinder(out, cancelSig);
            AIBinder_decStrong(cancelSig);
            return STATUS_OK;
        }
        case 5:   // detectInteraction()
        case 17:  // detectInteractionWithContext(OperationContext)
        {
            if (code == 17) skipParcelable(in);
            ALOGI("ISession::detectInteraction(tx=%u) -> unsupported", code);
            AIBinder* cancelSig = createCancellationSignal();
            writeOkStatus(out);
            AParcel_writeStrongBinder(out, cancelSig);
            AIBinder_decStrong(cancelSig);
            AIBinder* cb = acquireActiveCallback();
            if (cb) {
                postCallback([cb]() {
                    cbOnError(cb, 2 /* UNABLE_TO_PROCESS */, 0);
                    AIBinder_decStrong(cb);
                });
            }
            return STATUS_OK;
        }
        case 6: {  // enumerateEnrollments()
            ALOGI("ISession::enumerateEnrollments()");
            writeOkStatus(out);
            // Execute HAL enumerate asynchronously AFTER onTransact returns writeOkStatus(out)
            // so anc.hal.so's synchronous FingerprintOnEnumerate callback never races with
            // FingerprintInternalEnumerateClient::startHalOperation().
            postCallback([]() {
                {
                    std::lock_guard<std::mutex> lock(gSessionMutex);
                    gEnumIds.clear();
                }
                int ret = (gFpDevice && gFpDevice->enumerate) ? gFpDevice->enumerate(gFpDevice) : -1;
                if (ret != 0) {
                    ALOGW("HAL enumerate() returned %d -> sending empty list", ret);
                    AIBinder* cb = acquireActiveCallback();
                    if (cb) {
                        cbOnEnrollmentsEnumerated(cb, {});
                        AIBinder_decStrong(cb);
                    }
                }
            });
            return STATUS_OK;
        }
        case 7: {  // removeEnrollments(int32[] enrollmentIds)
            std::vector<int32_t> ids;
            readInt32ArrayVec(in, ids);
            int32_t uid = s->userId;
            ALOGI("ISession::removeEnrollments(count=%zu)", ids.size());
            writeOkStatus(out);
            if (ids.empty()) {
                AIBinder* cb = acquireActiveCallback();
                if (cb) {
                    postCallback([cb]() {
                        cbOnEnrollmentsRemoved(cb, {});
                        AIBinder_decStrong(cb);
                    });
                }
                return STATUS_OK;
            }
            postCallback([ids = std::move(ids), uid]() {
                {
                    std::lock_guard<std::mutex> lock(gSessionMutex);
                    gRemovedIds.clear();
                }
                for (int32_t fid : ids) {
                    if (gFpDevice && gFpDevice->remove) {
                        int ret = gFpDevice->remove(gFpDevice, static_cast<uint32_t>(uid),
                                                    static_cast<uint32_t>(fid));
                        ALOGI("HAL remove(gid=%d, fid=%d) -> %d", uid, fid, ret);
                    }
                }
            });
            return STATUS_OK;
        }
        case 8: {  // getAuthenticatorId()
            uint64_t id = (gFpDevice && gFpDevice->get_authenticator_id)
                                  ? gFpDevice->get_authenticator_id(gFpDevice)
                                  : 0;
            ALOGI("ISession::getAuthenticatorId() -> 0x%llx", (unsigned long long)id);
            writeOkStatus(out);
            AIBinder* cb = acquireActiveCallback();
            if (cb) {
                postCallback([cb, id]() {
                    cbOnAuthenticatorIdRetrieved(cb, static_cast<int64_t>(id));
                    AIBinder_decStrong(cb);
                });
            }
            return STATUS_OK;
        }
        case 9: {  // invalidateAuthenticatorId()
            uint64_t id = (gFpDevice && gFpDevice->get_authenticator_id)
                                  ? gFpDevice->get_authenticator_id(gFpDevice)
                                  : 0;
            ALOGI("ISession::invalidateAuthenticatorId() -> 0x%llx", (unsigned long long)id);
            writeOkStatus(out);
            AIBinder* cb = acquireActiveCallback();
            if (cb) {
                postCallback([cb, id]() {
                    cbOnAuthenticatorIdInvalidated(cb, static_cast<int64_t>(id));
                    AIBinder_decStrong(cb);
                });
            }
            return STATUS_OK;
        }
        case 10: {  // resetLockout(HardwareAuthToken)
            skipParcelable(in);
            ALOGI("ISession::resetLockout()");
            writeOkStatus(out);
            AIBinder* cb = acquireActiveCallback();
            if (cb) {
                postCallback([cb]() {
                    cbOnLockoutCleared(cb);
                    AIBinder_decStrong(cb);
                });
            }
            return STATUS_OK;
        }
        case 11: {  // close()
            ALOGI("ISession::close()");
            endFodOperation("session-close");
            if (gFpDevice && gFpDevice->cancel) {
                gFpDevice->cancel(gFpDevice);
            }
            AIBinder* cb = nullptr;
            {
                std::lock_guard<std::mutex> lock(gSessionMutex);
                s->closed = true;
                if (s->callback) {
                    cb = s->callback;
                    AIBinder_incStrong(cb);
                }
            }
            writeOkStatus(out);
            if (cb) {
                postCallback([cb]() {
                    cbOnSessionClosed(cb);
                    AIBinder_decStrong(cb);
                });
            }
            return STATUS_OK;
        }
        case 12: {  // onPointerDown(int pointerId, int x, int y, float minor, float major)
            int32_t pid = 0, x = 0, y = 0;
            float minor = 0, major = 0;
            AParcel_readInt32(in, &pid);
            AParcel_readInt32(in, &x);
            AParcel_readInt32(in, &y);
            AParcel_readFloat(in, &minor);
            AParcel_readFloat(in, &major);
            ALOGI("ISession::onPointerDown(pid=%d, x=%d, y=%d)", pid, x, y);
            onFodFingerEvent(true, x > 0 ? x : gFodCenterX, y > 0 ? y : gFodCenterY,
                             "onPointerDown", false);
            writeOkStatus(out);
            return STATUS_OK;
        }
        case 13: {  // onPointerUp(int pointerId)
            int32_t pid = 0;
            AParcel_readInt32(in, &pid);
            ALOGI("ISession::onPointerUp(pid=%d)", pid);
            onFodFingerEvent(false, gFodCenterX, gFodCenterY, "onPointerUp", false);
            writeOkStatus(out);
            return STATUS_OK;
        }
        case 14: {  // onUiReady()
            ALOGI("ISession::onUiReady()");
            setLocalHbm(true);
            triggerUiReady("onUiReady");
            writeOkStatus(out);
            return STATUS_OK;
        }
        case 18: {  // onPointerDownWithContext(PointerContext)
            skipParcelable(in);
            ALOGI("ISession::onPointerDownWithContext()");
            onFodFingerEvent(true, gFodCenterX, gFodCenterY, "onPointerDownWithContext", false);
            writeOkStatus(out);
            return STATUS_OK;
        }
        case 19:   // onPointerUpWithContext(PointerContext)
        case 21:   // onPointerCancelWithContext(PointerContext)
        {
            skipParcelable(in);
            ALOGI("ISession::onPointerUp/CancelWithContext(tx=%u)", code);
            onFodFingerEvent(false, gFodCenterX, gFodCenterY, "onPointerUpWithContext", false);
            writeOkStatus(out);
            return STATUS_OK;
        }
        case 20: {  // onContextChanged(OperationContext)
            skipParcelable(in);
            writeOkStatus(out);
            return STATUS_OK;
        }
        case 22: {  // setIgnoreDisplayTouches(bool)
            bool ignore = false;
            AParcel_readBool(in, &ignore);
            ALOGI("ISession::setIgnoreDisplayTouches(%d)", ignore ? 1 : 0);
            writeOkStatus(out);
            return STATUS_OK;
        }
        case kTxGetInterfaceVersion: {
            writeOkStatus(out);
            AParcel_writeInt32(out, kAidlFpVersion);
            return STATUS_OK;
        }
        case kTxGetInterfaceHash: {
            writeOkStatus(out);
            AParcel_writeString(out, kAidlFpHash, strlen(kAidlFpHash));
            return STATUS_OK;
        }
        default:
            ALOGW("ISession: unhandled tx=%u", code);
            return STATUS_UNKNOWN_TRANSACTION;
    }
}

// ============================================================================
// IFingerprint Implementation (AIDL V3 + Oplus 1019 sendFingerprintCmd)
// ============================================================================

static void ensureStoreDir(const std::string& path) {
    mkdir("/data/vendor_de", 0770);
    size_t pos = 1;
    while ((pos = path.find('/', pos)) != std::string::npos) {
        std::string sub = path.substr(0, pos);
        mkdir(sub.c_str(), 0770);
        pos++;
    }
    mkdir(path.c_str(), 0770);
}

static void writeSensorPropsList(AParcel* out) {
    // SensorProps[] array of length 1
    AParcel_writeInt32(out, 1);

    ParcelableWriter sp(out, true);
    {
        // 1. CommonProps
        ParcelableWriter cp(out, true);
        AParcel_writeInt32(out, 0);    // sensorId = 0
        AParcel_writeByte(out, 2);     // sensorStrength = STRONG (2)
        AParcel_writeInt32(out, 5);    // maxEnrollmentsPerUser = 5

        // ComponentInfo[] length 1
        AParcel_writeInt32(out, 1);
        {
            ParcelableWriter ci(out, true);
            const char* compId = "fingerprintSensor";
            const char* hwVer = gSensorVendor.c_str();
            const char* fwVer = "1.0";
            const char* serial = "";
            const char* swVer = "xiaomi-fod-aidl-v3";
            AParcel_writeString(out, compId, strlen(compId));
            AParcel_writeString(out, hwVer, strlen(hwVer));
            AParcel_writeString(out, fwVer, strlen(fwVer));
            AParcel_writeString(out, serial, strlen(serial));
            AParcel_writeString(out, swVer, strlen(swVer));
            ci.finish();
        }
        cp.finish();
    }

    // 2. sensorType = UNDER_DISPLAY_OPTICAL (3)
    AParcel_writeByte(out, 3);

    // 3. SensorLocation[] length 1
    AParcel_writeInt32(out, 1);
    {
        ParcelableWriter loc(out, true);
        AParcel_writeInt32(out, 0);            // displayId = 0
        AParcel_writeInt32(out, gFodCenterX);  // e.g. 540
        AParcel_writeInt32(out, gFodCenterY);  // e.g. 2109
        AParcel_writeInt32(out, gFodRadius);   // e.g. 93
        AParcel_writeString(out, "", 0);       // display = ""
        loc.finish();
    }

    // 4..7. booleans
    AParcel_writeBool(out, false);  // supportsNavigationGestures
    AParcel_writeBool(out, false);  // supportsDetectInteraction
    AParcel_writeBool(out, false);  // halHandlesDisplayTouches
    AParcel_writeBool(out, false);  // halControlsIllumination

    // 8. TouchDetectionParameters (V3)
    {
        ParcelableWriter tdp(out, true);
        AParcel_writeFloat(out, 1.0f);  // targetSize
        AParcel_writeFloat(out, 0.0f);  // minOverlap
        tdp.finish();
    }

    sp.finish();
}

static AIBinder_Class* gFpClass = nullptr;
static AIBinder_Class* gSessionCallbackClass = nullptr;

static void* onCreateFp(void* args) { return args; }
static void onDestroyFp(void*) {}
static void* onCreateCbProxy(void* args) { return args; }
static void onDestroyCbProxy(void*) {}
static binder_status_t onTransactCbProxy(AIBinder*, transaction_code_t, const AParcel*, AParcel*) {
    return STATUS_UNKNOWN_TRANSACTION;
}

static binder_status_t onTransactFp(
        AIBinder*, transaction_code_t code, const AParcel* in, AParcel* out) {
    switch (code) {
        case 1: {  // getSensorProps()
            ALOGI("IFingerprint::getSensorProps() -> UNDER_DISPLAY_OPTICAL (%d,%d r=%d)",
                  gFodCenterX, gFodCenterY, gFodRadius);
            writeOkStatus(out);
            writeSensorPropsList(out);
            return STATUS_OK;
        }
        case 2: {  // createSession(int sensorId, int userId, ISessionCallback cb)
            int32_t sensorId = 0, userId = 0;
            AIBinder* cbBinder = nullptr;
            AParcel_readInt32(in, &sensorId);
            AParcel_readInt32(in, &userId);
            AParcel_readStrongBinder(in, &cbBinder);
            ALOGI("IFingerprint::createSession(sensorId=%d, userId=%d, cb=%p)",
                  sensorId, userId, cbBinder);

            if (gFpDevice && gFpDevice->set_active_group) {
                // Dedicated SFS namespace (/data/vendor_de/<uid>/fpdata_cos) isolates ColorOS
                // templates from stock HyperOS 2 (/data/vendor_de/<uid>/fpdata) in shared MITEE
                // /mnt/vendor/persist/data so dual-booting via DSU never wipes templates.
                char storePath[128];
                snprintf(storePath, sizeof(storePath), "/data/vendor_de/%d/fpdata_cos", userId);
                ensureStoreDir(storePath);
                int ret = gFpDevice->set_active_group(gFpDevice, static_cast<uint32_t>(userId), storePath);
                ALOGI("HAL set_active_group(%d, %s) -> %d", userId, storePath, ret);
            }

            if (!gSessionCallbackClass) {
                gSessionCallbackClass = AIBinder_Class_define(
                        kISessionCallbackDescriptor, onCreateCbProxy, onDestroyCbProxy,
                        onTransactCbProxy);
            }
            if (cbBinder) {
                bool ok = AIBinder_associateClass(cbBinder, gSessionCallbackClass);
                ALOGI("AIBinder_associateClass(ISessionCallback) -> %d", ok ? 1 : 0);
            }

            if (!gSessionClass) {
                gSessionClass = AIBinder_Class_define(
                        kISessionDescriptor, onCreateSession, onDestroySession, onTransactSession);
            }
            auto* state = new SessionState();
            state->sensorId = sensorId;
            state->userId = userId;
            state->callback = cbBinder;  // owns ref from AParcel_readStrongBinder
            state->closed = false;

            {
                std::lock_guard<std::mutex> lock(gSessionMutex);
                gActiveSession = state;
            }

            AIBinder* sessionBinder = AIBinder_new(gSessionClass, state);
            AIBinder_markVintfStability(sessionBinder);
            writeOkStatus(out);
            AParcel_writeStrongBinder(out, sessionBinder);
            AIBinder_decStrong(sessionBinder);
            return STATUS_OK;
        }
        case kOplusTxSendFpCmd: {  // Oplus sendFingerprintCmd(int cmdId, int bufLen, byte[] inBuf)
            int32_t cmdId = 0, bufLen = 0;
            std::vector<uint8_t> buf;
            AParcel_readInt32(in, &cmdId);
            AParcel_readInt32(in, &bufLen);
            readByteArrayVec(in, buf);
            int32_t firstVal = 0;
            if (buf.size() >= 4) {
                memcpy(&firstVal, buf.data(), 4);
            } else if (!buf.empty()) {
                firstVal = buf[0];
            }
            int32_t retVal = 0;
            if (cmdId == kOplusInCmdScreenState) {
                bool on = (firstVal != 0);
                gScreenOn.store(on);
                ALOGI("Oplus sendFingerprintCmd(1019): SCREEN_STATE -> %s", on ? "ON" : "OFF");
            } else if (cmdId == kOplusInCmdGetEnrollTotalTimes) {
                // Return -1 so ColorOS FingerprintEnrollProcessor computes
                // mEnrollmentSteps = remaining + 1 dynamically from the first enroll step.
                retVal = -1;
                ALOGI("Oplus sendFingerprintCmd(1019): GET_ENROLLMENT_TOTAL_TIMES(1010) -> -1 (dynamic)");
            } else {
                ALOGI("Oplus sendFingerprintCmd(1019): cmdId=%d bufLen=%d actualSize=%zu first=%d -> OK(0)",
                      cmdId, bufLen, buf.size(), firstVal);
            }
            writeOkStatus(out);
            AParcel_writeInt32(out, retVal);
            return STATUS_OK;
        }
        case kTxGetInterfaceVersion: {
            writeOkStatus(out);
            AParcel_writeInt32(out, kAidlFpVersion);
            return STATUS_OK;
        }
        case kTxGetInterfaceHash: {
            writeOkStatus(out);
            AParcel_writeString(out, kAidlFpHash, strlen(kAidlFpHash));
            return STATUS_OK;
        }
        default: {
            if (code >= 1000 && code < 0x00ffff00u) {
                ALOGI("Oplus custom IFingerprint tx=%u -> OK(0)", code);
                writeOkStatus(out);
                AParcel_writeInt32(out, 0);
                return STATUS_OK;
            }
            ALOGW("IFingerprint: unknown tx=%u", code);
            return STATUS_UNKNOWN_TRANSACTION;
        }
    }
}

static bool openFingerprintHal() {
    const char* candidates[][2] = {
        {"jiiov", "/vendor/lib64/hw/fingerprint.jiiov.so"},
        {"goodix_fod", "/vendor/lib64/hw/fingerprint.goodix_fod.so"},
        {"goodix", "/vendor/lib64/hw/fingerprint.goodix.so"},
        {"fpc_fod", "/vendor/lib64/hw/fingerprint.fpc_fod.so"},
        {"silead", "/vendor/lib64/hw/fingerprint.silead.so"},
    };

    for (auto& cand : candidates) {
        const char* vendor = cand[0];
        const char* path = cand[1];
        if (access(path, R_OK) != 0) continue;
        ALOGI("Probing fingerprint HAL module: %s (%s)", vendor, path);
        void* handle = dlopen(path, RTLD_NOW);
        if (!handle) {
            ALOGW("dlopen(%s) failed: %s", path, dlerror());
            continue;
        }
        auto* hmi = reinterpret_cast<const hw_module_t*>(dlsym(handle, "HMI"));
        if (!hmi || !hmi->methods || !hmi->methods->open) {
            ALOGW("Invalid HMI in %s", path);
            dlclose(handle);
            continue;
        }
        hw_device_t* dev = nullptr;
        int err = hmi->methods->open(hmi, "fingerprint", &dev);
        if (err != 0 || !dev) {
            ALOGW("open(%s) failed: err=%d", path, err);
            dlclose(handle);
            continue;
        }
        gFpDevice = reinterpret_cast<fingerprint_device_t*>(dev);
        gSensorVendor = vendor;
        if (gFpDevice->set_notify) {
            int nret = gFpDevice->set_notify(gFpDevice, halNotifyCallback);
            ALOGI("Opened %s HAL successfully! set_notify=%d extCmd=%p",
                  vendor, nret, reinterpret_cast<void*>(gFpDevice->extCmd));
        }
        return true;
    }
    return false;
}

}  // namespace

static int runSelfTest() {
    printf("[FodAidlBridge v5] Running self-test...\n");
    loadFodGeometryFromProps();
    startCallbackWorker();
    printf("  geometry: center=(%d,%d) radius=%d\n", gFodCenterX, gFodCenterY, gFodRadius);

    gFpClass = AIBinder_Class_define(kIFingerprintDescriptor, onCreateFp, onDestroyFp, onTransactFp);
    AIBinder* fp = AIBinder_new(gFpClass, nullptr);
    AIBinder_markVintfStability(fp);

    // 1. Test getInterfaceVersion
    AParcel *in = nullptr, *out = nullptr;
    AStatus* st = nullptr;
    int32_t ver = -1;
    AIBinder_prepareTransaction(fp, &in);
    binder_status_t bstat = AIBinder_transact(fp, kTxGetInterfaceVersion, &in, &out, 0);
    if (bstat == STATUS_OK && out) {
        AParcel_readStatusHeader(out, &st);
        AParcel_readInt32(out, &ver);
        AParcel_delete(out);
    }
    printf("  getInterfaceVersion: bstat=%d ok=%d ver=%d\n", bstat, st ? AStatus_isOk(st) : 0, ver);
    if (st) AStatus_delete(st);

    // 2. Test getSensorProps
    in = nullptr; out = nullptr; st = nullptr;
    AIBinder_prepareTransaction(fp, &in);
    bstat = AIBinder_transact(fp, 1, &in, &out, 0);
    int32_t arrLen = -1, sensorId = -1, maxEnroll = -1;
    int8_t strength = -1, stype = -1;
    if (bstat == STATUS_OK && out) {
        AParcel_readStatusHeader(out, &st);
        AParcel_readInt32(out, &arrLen);
        int32_t spNonNull = 0, spSize = 0;
        AParcel_readInt32(out, &spNonNull);
        AParcel_readInt32(out, &spSize);
        int32_t cpNonNull = 0, cpSize = 0;
        AParcel_readInt32(out, &cpNonNull);
        int32_t cpStart = AParcel_getDataPosition(out);
        AParcel_readInt32(out, &cpSize);
        AParcel_readInt32(out, &sensorId);
        AParcel_readByte(out, &strength);
        AParcel_readInt32(out, &maxEnroll);
        AParcel_setDataPosition(out, cpStart + cpSize);
        AParcel_readByte(out, &stype);
        AParcel_delete(out);
    }
    printf("  getSensorProps: bstat=%d ok=%d arrLen=%d sensorId=%d strength=%d maxEnroll=%d type=%d\n",
           bstat, st ? AStatus_isOk(st) : 0, arrLen, sensorId, strength, maxEnroll, stype);
    if (st) AStatus_delete(st);

    // 3. Test Oplus sendFingerprintCmd (1019) screen state tracking (1011)
    in = nullptr; out = nullptr; st = nullptr;
    AIBinder_prepareTransaction(fp, &in);
    AParcel_writeInt32(in, kOplusInCmdScreenState);
    AParcel_writeInt32(in, 4);
    int8_t offPayload[4] = {0, 0, 0, 0};
    AParcel_writeByteArray(in, offPayload, 4);
    bstat = AIBinder_transact(fp, kOplusTxSendFpCmd, &in, &out, 0);
    int32_t cmdRet = -1;
    if (bstat == STATUS_OK && out) {
        AParcel_readStatusHeader(out, &st);
        AParcel_readInt32(out, &cmdRet);
        AParcel_delete(out);
    }
    bool screenOffTracked = !gScreenOn.load();
    printf("  Oplus sendFingerprintCmd(1011=0): bstat=%d ret=%d screenOffTracked=%d\n",
           bstat, cmdRet, screenOffTracked ? 1 : 0);
    if (st) AStatus_delete(st);

    // 3b. Test Oplus sendFingerprintCmd (1019) getEnrollmentTotalTimes (1010) -> -1
    in = nullptr; out = nullptr; st = nullptr;
    AIBinder_prepareTransaction(fp, &in);
    AParcel_writeInt32(in, kOplusInCmdGetEnrollTotalTimes);
    AParcel_writeInt32(in, 4);
    AParcel_writeByteArray(in, offPayload, 4);
    bstat = AIBinder_transact(fp, kOplusTxSendFpCmd, &in, &out, 0);
    int32_t totalTimesRet = 0;
    if (bstat == STATUS_OK && out) {
        AParcel_readStatusHeader(out, &st);
        AParcel_readInt32(out, &totalTimesRet);
        AParcel_delete(out);
    }
    printf("  Oplus sendFingerprintCmd(1010=getEnrollmentTotalTimes): bstat=%d ret=%d\n",
           bstat, totalTimesRet);
    if (st) AStatus_delete(st);

    // 4. Test outbound ISessionCallback tx 1001 (onFingerprintCmd 1201/1202)
    static int32_t sGotCmd = 0;
    static int32_t sGotLen = 0;
    auto dummyCreate = [](void* a) -> void* { return a; };
    auto dummyDestroy = [](void*) {};
    auto mockCbTransact = [](AIBinder*, transaction_code_t code, const AParcel* cIn, AParcel* cOut) -> binder_status_t {
        if (code == kOplusCbTxOnFingerprintCmd) {
            int32_t cid = 0, clen = 0;
            std::vector<uint8_t> bytes;
            AParcel_readInt32(cIn, &cid);
            AParcel_readInt32(cIn, &clen);
            readByteArrayVec(cIn, bytes);
            sGotCmd = cid;
            sGotLen = static_cast<int32_t>(bytes.size());
            writeOkStatus(cOut);
            return STATUS_OK;
        }
        return STATUS_UNKNOWN_TRANSACTION;
    };
    AIBinder_Class* mockCbCls = AIBinder_Class_define(
            kISessionCallbackDescriptor, dummyCreate, dummyDestroy, mockCbTransact);
    AIBinder* mockCb = AIBinder_new(mockCbCls, nullptr);
    uint8_t tsBytes[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    cbOnFingerprintCmd(mockCb, kOplusCmdTouchDown, tsBytes, 8);
    printf("  ISessionCallback onFingerprintCmd(tx=1001): cmdId=%d byteLen=%d\n", sGotCmd, sGotLen);
    AIBinder_decStrong(mockCb);

    AIBinder_decStrong(fp);
    return (ver == 3 && arrLen == 1 && sensorId == 0 && strength == 2 && stype == 3 &&
            cmdRet == 0 && totalTimesRet == -1 && screenOffTracked && sGotCmd == 1201 && sGotLen == 8)
                   ? 0
                   : 1;
}

int main(int argc, char** argv) {
    if (argc > 1 && strcmp(argv[1], "--self-test") == 0) {
        return runSelfTest();
    }

    ALOGI("FodAidlBridge v5 starting (Xiaomi Optical FOD -> ColorOS 17 AIDL V3, isolated fpdata_cos + async cb)...");
    loadFodGeometryFromProps();
    startCallbackWorker();

    if (!openFingerprintHal()) {
        ALOGE("Failed to open any Xiaomi fingerprint HAL module! Exiting.");
        return 1;
    }

    // Start hardware FOD monitor threads
    std::thread(uiReadyFallbackLoop).detach();
    std::thread(displayMonitorLoop).detach();
    std::thread(touchMonitorLoop).detach();

    ABinderProcess_setThreadPoolMaxThreadCount(4);
    ABinderProcess_startThreadPool();

    gFpClass = AIBinder_Class_define(kIFingerprintDescriptor, onCreateFp, onDestroyFp, onTransactFp);
    AIBinder* fpBinder = AIBinder_new(gFpClass, nullptr);
    AIBinder_markVintfStability(fpBinder);

    binder_status_t status = AServiceManager_addService(fpBinder, kIFingerprintInstance);
    if (status != STATUS_OK) {
        ALOGE("AServiceManager_addService(%s) failed: %d", kIFingerprintInstance, status);
        return 1;
    }
    ALOGI("Registered %s successfully! Joining thread pool...", kIFingerprintInstance);

    ABinderProcess_joinThreadPool();
    ALOGE("ABinderProcess_joinThreadPool() exited unexpectedly!");
    return 1;
}
