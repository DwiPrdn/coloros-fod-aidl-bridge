# ColorOS 17 Optical FOD (Fingerprint) AIDL V3 Bridge (`tanzanite`)

A standalone, zero-`libc++_shared.so` native C++ AIDL V3 Fingerprint HAL bridge (`FodAidlBridge v5`) that connects **Xiaomi's legacy optical under-display fingerprint HAL (`fingerprint.jiiov.so` / `fingerprint.goodix_fod.so`) + Xiaomi display LHBM (`/dev/mi_display/disp_feature`) + touch FOD (`/dev/xiaomi-touch`, `fod_press_status`, `BTN_INFO`)** directly to **ColorOS 17 `IFingerprint` V3 + Oplus custom FOD transactions (`1019` / `1001`)**.

> [!IMPORTANT]
> **Sensor Support Notice**:
> - **Tested & confirmed working**: **Jiiov** (`fingerprint.jiiov.so`) and **Goodix** (`fingerprint.goodix_fod.so`) optical FOD sensors on Redmi Note 14 4G (`tanzanite`) under **SELinux Enforcing**.
> - **Untested**: **FPC** (`fingerprint.fpc_fod.so`) and **Silead** (`fingerprint.silead.so`). Fallback probe paths exist in `openFingerprintHal()`, but FPC/Silead variants have not been tested on hardware — their `extCmd` / vendor acquired codes may differ.

---

## Test Environment & ROM Baseline

| Component | Details |
| :--- | :--- |
| **Test Device** | Redmi Note 14 4G (`tanzanite`, SKU `tanzanite_n_gl`) |
| **SoC / ABI** | MediaTek Helio G99-Ultra (`MT6789`), `arm64-v8a`, VNDK 31 |
| **Display** | 1080×2400 AMOLED (`panel_o7_38_0c_0a_dsc_vdo`, FOD center `(540, 2109)`, radius `93 px`) |
| **Optical Sensors Tested** | **Jiiov (`fingerprint.jiiov.so`) & Goodix (`fingerprint.goodix_fod.so`) + MITEE TEE** |
| **Kernel** | `5.10.251-HayaseYuuka-v3.4-MillenniumTeam+` (**SELinux Enforcing**) — also tested on `5.10.269-EvernightKernel-Android-PERMISSIVE` |
| **Stock Firmware (Base Vendor)** | HyperOS 2 — `OS2.0.214.0.VOGEUXM` (`Redmi/tanzanite/tanzanite:12/SP1A.210812.016/OS2.0.214.0.VOGEUXM:user/release-keys`, Android 12 / SDK 31 vendor) |
| **ColorOS Version** | ColorOS 17 (`V17.0.0`, Android 17 / SDK 37) |
| **ColorOS Base ROM** | OnePlus Ace 5 Ultra CN (`PLC110`), `PLC110_11_A.01` (`PLC110_11.A.01_001_202610210112`, `CP2A.260605.016 release-keys`) |
| **Deployment Method** | DSU (`vendor.img` repacked with `mkfs.erofs`) |

---

## What Is Bridged

| Layer | Target / Backend |
| :--- | :--- |
| **Exposed Service** | `android.hardware.biometrics.fingerprint.IFingerprint/default` (Stable AIDL V3, hash `637371b53fb7faf9bd43aa51b72c23852d6e6d96`, `UNDER_DISPLAY_OPTICAL`) |
| **ColorOS Custom Binder Protocol** | Inbound `IFingerprint::sendFingerprintCmd` (tx `1019`: `1010` enroll total steps, `1011` screen state)<br>Outbound `ISessionCallback::onFingerprintCmd` (tx `1001`: `1201` touch-down + uptimeMillis, `1202` touch-up) |
| **Legacy Vendor HAL Backend** | Auto-probed via `dlopen()`: `fingerprint.jiiov.so` & `fingerprint.goodix_fod.so` (**tested & working**); fallback probes for `goodix`/`fpc_fod`/`silead` (untested) via `fingerprint_device_t` + Xiaomi `extCmd()` |
| **Display Illumination (LHBM)** | `/dev/mi_display/disp_feature` — `MI_DISP_IOCTL_SET_LOCAL_HBM` (`0x400c440e`, mode `2 = LOCAL_HBM_NORMAL_WHITE_1200NIT`) & `MI_DISP_IOCTL_REGISTER_EVENT` (`0x400c4407`, `MI_DISP_EVENT_FOD = 2`) |
| **Touch FOD Hardware** | `/dev/xiaomi-touch` (`0x5400`, `TOUCH_MODE_FOD_ENABLE = 10`), `/sys/class/touch/touch_dev/fod_press_status` (`POLLPRI`), and `/dev/input/event*` (`BTN_INFO = 0x152` + `ABS_MT_POSITION_{X,Y}`) |
| **Replaces Stock Binary** | `/vendor/bin/hw/android.hardware.biometrics.fingerprint@2.1-service` (HIDL 2.1, incompatible with ColorOS 17 AIDL V3 + Oplus FOD UI pipeline) |

---

## Files Bridged / Modified

| File Path | Action | Mode / Owner | SELinux Context |
| :--- | :--- | :--- | :--- |
| `vendor/bin/hw/android.hardware.biometrics.fingerprint-service.tanzanite` | **Added** | `0755` (`0:2000`) | `u:object_r:hal_fingerprint_default_exec:s0` |
| `vendor/etc/init/android.hardware.biometrics.fingerprint@2.1-service.rc` | **Replaced** | `0644` (`0:0`) | `u:object_r:vendor_configs_file:s0` |
| `vendor/etc/vintf/manifest/android.hardware.biometrics.fingerprint@2.1-service.xml` | **Replaced** | `0644` (`0:0`) | `u:object_r:vendor_configs_file:s0` |

### Required Stock Vendor Files (Keep Unmodified from Base Vendor)
- `/vendor/lib64/hw/fingerprint.jiiov.so` and/or `/vendor/lib64/hw/fingerprint.goodix_fod.so` (and their MITEE/vendor dependencies)
- `/dev/mi_display/disp_feature` (Xiaomi display feature kernel driver supporting `MI_DISP_IOCTL_SET_LOCAL_HBM` mode `2`)
- `/dev/xiaomi-touch` and `/sys/class/touch/touch_dev/fod_press_status` (Xiaomi touch driver supporting `TOUCH_MODE_FOD_ENABLE = 10`)

---

## Required Properties & ColorOS Feature XMLs (FOD Integration Guide)

Having the AIDL binary alone is **not** enough for ColorOS 17 to render the FOD icon, pressed animation, and Local HBM correctly. Make sure the following properties and ColorOS feature XMLs are present in your port:

### 1. Vendor Properties (`vendor/build.prop`)
```ini
# FOD sensor geometry (top-left X,Y and width,height in pixels for 1080x2400 panel)
# FodAidlBridge reads these dynamically at boot and computes:
#   centerX = X + W/2 = 447 + 93 = 540
#   centerY = Y + H/2 = 2016 + 93 = 2109
#   radius  = W/2     = 93
# Adjust these two lines to match YOUR device's physical optical sensor position!
persist.vendor.sys.fp.fod.location.X_Y=447,2016
persist.vendor.sys.fp.fod.size.width_height=186,186

# Xiaomi / MTK FOD & Local HBM flags
ro.hardware.fp.fod=true
ro.hardware.fp.fod.location=low
ro.hardware.fp.fod.touch.ctl.version=2.0
ro.vendor.localhbm.enable=true

# CRITICAL: Disable software dimlayer (bridge uses hardware Local HBM 1200 nit white circle)
ro.vendor.fod.dimlayer.enable=false
ro.vendor.display.fod_monitor_default_fps=120

# CRITICAL on MTK devices without native MTK hardware AOD: prevents SOFOD/AOD freeze
ro.vendor.mtk_aod_support=0
```
*(Fallback geometry props also checked by `FodAidlBridge` if the above are absent: `persist.vendor.fingerprint.optical.sensorlocation` and `persist.vendor.fingerprint.optical.iconsize`.)*

### 2. ColorOS Feature XMLs (`my_product/etc/permissions/`)
Add/verify these in **`my_product/etc/permissions/oplus.product.display_features.xml`**:
```xml
<!-- Screen fingerprint feature (hardware Local HBM, disable software dimlayer) -->
<!-- NOTE: "fingeprint" (missing 'r') is the EXACT upstream ColorOS spelling! Do NOT "fix" the typo! -->
<oplus-feature name="oplus.software.fingeprint_optical_enabled"/>
<oplus-feature name="oplus.software.display.fingerprint_disable_dimlayer"/>
<oplus-feature name="oplus.software.display.local_hbm_support"/>
<oplus-feature name="oplus.software.display.aod_support"/>
```
And verify **`my_product/etc/permissions/android.hardware.fingerprint.xml`** declares:
```xml
<permissions>
    <feature name="android.hardware.fingerprint" />
</permissions>
```
And in **`my_product/build.prop`** (usually present in stock ColorOS `my_product`):
```ini
persist.sys.block.fingerprint=true
```

### 3. Template Storage Directory & SELinux Context
- `FodAidlBridge` stores ColorOS templates in **`/data/vendor_de/<userId>/fpdata_cos`** (`0770 system:system`) instead of `/data/vendor_de/0/fpdata` so dual-booting DSU ColorOS alongside host HyperOS never wipes either OS's fingerprints.
- Under SELinux Enforcing, `/data/vendor_de/[0-9]+/fpdata_cos(/.*)?` MUST be labeled `u:object_r:vendor_fingerprint_data_file:s0` (see [`config/selinux_enforcing.cil.snippet`](config/selinux_enforcing.cil.snippet)).

---

## How the Logic Works

### Why Stock Xiaomi Fingerprint HAL Breaks on ColorOS 17
1. **HIDL 2.1 vs AIDL V3**: ColorOS 17 expects `android.hardware.biometrics.fingerprint.IFingerprint/default` V3 (`UNDER_DISPLAY_OPTICAL`, `SensorLocation`, `TouchDetectionParameters`) and does not work properly with Xiaomi's legacy HIDL 2.1 daemon.
2. **Xiaomi Optical FOD Sequence**: Xiaomi's optical sensors (`fingerprint.jiiov.so` / `fingerprint.goodix_fod.so`) will **not** capture a valid fingerprint image unless:
   - `/dev/xiaomi-touch` has `TOUCH_MODE_FOD_ENABLE (10)` enabled,
   - Local HBM is turned ON via `/dev/mi_display/disp_feature` (`mode = 2` = `LOCAL_HBM_NORMAL_WHITE_1200NIT`; mode `4` is green 500 nit factory test and blinds the sensor!),
   - `extCmd(1, 1)` (finger down), `extCmd(2, x)` / `extCmd(3, y)`, and `extCmd(10, 1)` (`UI_READY` once `MI_DISP_EVENT_FOD` fires) are delivered in exact order.
3. **ColorOS 17 FOD UI Synchronization**: ColorOS SystemUI requires custom outbound callback `ISessionCallback::onFingerprintCmd` (tx `1001`) with `cmdId=1201` (touch-down + 8-byte LE `uptimeMillis`) and `cmdId=1202` (touch-up) to drive the pressed icon animation and screen-off wake pipeline, plus `sendFingerprintCmd(1019, cmdId=1010)` returning `-1` so enrollment computes total steps dynamically (`remaining + 1`).
4. **Synchronous Enumeration Race Condition**: `fingerprint.jiiov.so` invokes `FINGERPRINT_TEMPLATE_ENUMERATING` synchronously *inside* `enumerate()`. Forwarding that callback before `ISession::enumerateEnrollments()` returns `STATUS_OK` races with `FingerprintInternalEnumerateClient` in `system_server`.
5. **DSU Dual-Boot Template Isolation**: Sharing `/data/vendor_de/0/fpdata` between host HyperOS 2 and DSU ColorOS 17 causes `FingerprintService` to wipe templates across reboots due to mismatched `authenticatorId` / framework DB records.

### Bridge Architecture

```mermaid
flowchart TD
    SYS["ColorOS 17 system_server & SystemUI<br/>FingerprintServiceProviderExtImpl"]
    SYS <-->|"IFingerprint V3 + ISession (tx 1..22) + tx 1019<br/>ISessionCallback (tx 1..16) + tx 1001 (1201/1202)"| BRIDGE["FodAidlBridge v5<br/>(android.hardware.biometrics.fingerprint-service.tanzanite)"]

    BRIDGE -->|"FIFO Async Callback Worker Thread"| SYS
    BRIDGE -->|"dlopen + fingerprint_device_t<br/>extCmd(1=touch, 2/3=XY, 10=UI_READY)<br/>store: /data/vendor_de/0/fpdata_cos"| JIIOV["fingerprint.jiiov.so / fingerprint.goodix_fod.so<br/>(Tested: Jiiov & Goodix / MITEE TEE)"]

    TOUCH["TouchMonitorThread<br/>POLLPRI fod_press_status + /dev/input/event* BTN_INFO"] -->|"FOD Down/Up + (x,y)"| BRIDGE
    DISP["DisplayMonitorThread<br/>MI_DISP_IOCTL_REGISTER_EVENT (FOD=2)"] -->|"MI_DISP_EVENT_FOD != 0 -> UI_READY"| BRIDGE
    FB["UiReadyFallbackThread<br/>80ms (screen ON) / 350ms (screen OFF)"] -->|"Safety UI_READY"| BRIDGE

    BRIDGE -->|"ioctl 0x5400 {10, 1/0}"| XTOUCH["/dev/xiaomi-touch"]
    BRIDGE -->|"MI_DISP_IOCTL_SET_LOCAL_HBM (0 or 2=WHITE_1200NIT)"| MDISP["/dev/mi_display/disp_feature"]
```

### Detailed Implementation Breakdown
1. **Dynamic FOD Geometry (`loadFodGeometryFromProps`)**:
   - Reads `persist.vendor.sys.fp.fod.location.X_Y` and `persist.vendor.sys.fp.fod.size.width_height` at startup (converting top-left + width/height into center `(540, 2109)` and radius `93`) and reports it in `IFingerprint::getSensorProps()` as `UNDER_DISPLAY_OPTICAL (3)` with `STRONG (2)` strength and `maxEnrollmentsPerUser = 5`.
2. **Dual-Boot Template Persistence (`/data/vendor_de/<uid>/fpdata_cos`)**:
   - `IFingerprint::createSession()` creates `/data/vendor_de/<uid>/fpdata_cos` (`0770 system:system`) and passes it to `set_active_group()`, keeping ColorOS templates isolated from stock HyperOS 2's `/data/vendor_de/0/fpdata` in MITEE secure storage.
3. **Ordered Asynchronous Callback Queue (`cbWorkerLoop` / `postCallback`)**:
   - All outbound `ISessionCallback` calls (`onChallengeGenerated`, `onEnrollmentProgress`, `onAuthenticationSucceeded`, `onEnrollmentsEnumerated`, `onEnrollmentsRemoved`, `onFingerprintCmd`, etc.) are dispatched on a single FIFO worker thread *after* `ISession::onTransact` replies `STATUS_OK`, completely eliminating re-entrant binder deadlocks and enumeration races.
4. **Hardware FOD Capture Pipeline (`onFodFingerEvent`)**:
   - **Touch detection**: `TouchMonitorThread` watches both `/sys/class/touch/touch_dev/fod_press_status` (`POLLPRI`) and `/dev/input/event*` (`BTN_INFO = 0x152` + scaled `ABS_MT_POSITION_X/Y`), with automatic coordinate hit-testing fallback if `fod_press_status` is absent.
   - **On Finger Down**:
     1. Immediately sends ColorOS `onFingerprintCmd(1001, cmdId=1201, uptimeMillis)` so the pressed glow and screen-off wake pipeline start with zero latency.
     2. Sends touch `(x, y)` via `extCmd(2, x)` / `extCmd(3, y)`.
     3. Enables Local HBM (`MI_DISP_IOCTL_SET_LOCAL_HBM`, `value = 2` white 1200 nit).
     4. Signals `extCmd(1, 1)` (finger down) to the loaded optical HAL (`fingerprint.jiiov.so` / `fingerprint.goodix_fod.so`).
     5. Waits for `DisplayMonitorThread` to receive `MI_DISP_EVENT_FOD != 0` (typically ~16–32 ms), then immediately fires `extCmd(10, 1)` (`UI_READY`). A fallback timer (`80 ms` screen-on, `350 ms` screen-off) guarantees capture never stalls.
   - **Post-Capture / Finger Up**:
     - Immediately turns off `extCmd(10, 0)`, Local HBM (`value = 0`), and sends `cmdId=1202` (touch-up) so the white circle never lingers after enrollment steps or failed matches.
5. **Acquired / Vendor Code Filtering (`halNotifyCallback`)**:
   - Filters proprietary Jiiov internal notifications (`type == 7`, acquired codes `1020, 1022, 1023, 1025`) that confuse ColorOS UI.
   - Translates Jiiov low-contrast frame `1041` to standard AIDL `INSUFFICIENT (3)`.
   - Converts `hw_auth_token_t` (69-byte packed struct with big-endian `authenticator_type` & `timestamp`) losslessly to/from AIDL `HardwareAuthToken`.
6. **Runtime Debug Log Toggle (`bridge_log.h`)**:
   - Quiet by default (only 1-line boot banner and `ALOGE` errors logged). Toggle live without rebooting:
     ```bash
     adb shell setprop persist.vendor.cos.bridge.debug 1   # enable verbose logs
     adb shell setprop persist.vendor.cos.bridge.debug 0   # silence verbose logs
     ```

---

## SELinux Enforcing Policy

See [`config/selinux_enforcing.cil.snippet`](config/selinux_enforcing.cil.snippet) for the audited Android 17 / VNDK 31 CIL rules for `hal_fingerprint_default` (`touchfeature_device`, `input_device_31_0`, `vendor_displayfeature_device`, `vendor_sysfs_displayfeature`, `vendor_fingerprint_data_file`, `servicemanager_31_0`, and binder client pairs).

---

## Installation (Vendor Overlay)

1. Copy the files from `vendor/` (or the `v1.1.0` release archive) into your port's vendor tree:
   - `vendor/bin/hw/android.hardware.biometrics.fingerprint-service.tanzanite`
   - `vendor/etc/init/android.hardware.biometrics.fingerprint@2.1-service.rc`
   - `vendor/etc/vintf/manifest/android.hardware.biometrics.fingerprint@2.1-service.xml`
2. Add the entries from [`config/vendor_fs_config.snippet`](config/vendor_fs_config.snippet) and [`config/vendor_file_contexts.snippet`](config/vendor_file_contexts.snippet).
3. Add the required properties & ColorOS feature XMLs listed above.
4. If running **SELinux Enforcing**, merge [`config/selinux_enforcing.cil.snippet`](config/selinux_enforcing.cil.snippet) into your vendor SELinux policy (and recompile `precompiled_sepolicy`).
5. Repack `vendor.img`.

---

## Building from Source

```bash
export NDK_DIR=/path/to/android-ndk-r27c
export BINDER_NDK=/path/to/stock_cos/system/system/lib64/libbinder_ndk.so
./build.sh
```

Zero `libc++_shared.so` dependency (`-static-libstdc++`).

---

## Verification & Self-Test

```bash
adb push vendor/bin/hw/android.hardware.biometrics.fingerprint-service.tanzanite /data/local/tmp/fod_test
adb shell 'chmod 755 /data/local/tmp/fod_test && /data/local/tmp/fod_test --self-test'
# Expected: exit code 0, ver=3, type=3 (UNDER_DISPLAY_OPTICAL), cmd 1010 -> -1, tx 1001 cmdId=1201 OK

adb shell service check android.hardware.biometrics.fingerprint.IFingerprint/default
adb shell dumpsys fingerprint
```

---

## Troubleshooting Guide

First, enable live verbose logging:
```bash
adb shell setprop persist.vendor.cos.bridge.debug 1
adb logcat -s FodAidlBridge FingerprintService OnScreenFingerprint
```

| Symptom | Likely Cause | How to Check & Fix |
| :--- | :--- | :--- |
| **No Fingerprint menu in Settings** | Service not registered, VINTF manifest mismatch, or missing `android.hardware.fingerprint` feature | Run `adb shell service check android.hardware.biometrics.fingerprint.IFingerprint/default`. If `not found`, check `logcat -d \| grep -iE 'FodAidlBridge\|fps_hal\|avc:.*fingerprint'`. Also verify `android.hardware.fingerprint.xml` is in `my_product/etc/permissions/`. |
| **FOD icon or pressed animation does not appear** | Missing `oplus.software.fingeprint_optical_enabled` (check exact spelling without `r`!) or `IFingerprint::getSensorProps` not reporting `UNDER_DISPLAY_OPTICAL (3)` | Run `adb shell pm list features \| grep fingeprint` and `adb shell dumpsys fingerprint \| grep -iE 'type\|location\|radius'`. Verify `FodAidlBridge` logs `onFingerprintCmd(1001, cmdId=1201)` on touch-down and `1202` on touch-up. |
| **FOD icon is off-center / misaligned with sensor** | Wrong `persist.vendor.sys.fp.fod.location.X_Y` or `size.width_height` for your panel | Check `adb shell getprop \| grep fp.fod`. Remember `X_Y` is **top-left**, NOT center: `X = centerX - W/2`, `Y = centerY - H/2`. Verify computed `(cx, cy, r)` in `dumpsys fingerprint`. |
| **Whole screen dims/blacks out or flickers when pressing FOD** | ColorOS software dimlayer is still enabled alongside hardware Local HBM | Verify `oplus.software.display.fingerprint_disable_dimlayer` and `oplus.software.display.local_hbm_support` are in `oplus.product.display_features.xml`, AND `ro.vendor.fod.dimlayer.enable=false` + `ro.vendor.localhbm.enable=true` in `vendor/build.prop`. |
| **Finger pressed on icon, animation plays, but sensor never reads / green dot appears** | LHBM ioctl failed (`/dev/mi_display/disp_feature` permission/SELinux), wrong LHBM mode (`4` green vs `2` white 1200 nit), or untested sensor `extCmd` mismatch | Check `FodAidlBridge` log for `MI_DISP_IOCTL_SET_LOCAL_HBM` and `MI_DISP_EVENT_FOD` / `UI_READY`. If `open(/dev/mi_display/disp_feature)` fails with `EACCES`, check `vendor_displayfeature_device` SELinux rule (`logcat -d \| grep avc:.*disp_feature`). |
| **Touching FOD circle produces zero logs in `FodAidlBridge`** | Touch FOD mode (`TOUCH_MODE_FOD_ENABLE=10`) failed on `/dev/xiaomi-touch` or SELinux blocked `touchfeature_device` / `input_device` | Check `FodAidlBridge` logs for `open(/dev/xiaomi-touch)` and `fod_press_status` / `BTN_INFO`. Verify `hal_fingerprint_default` has `touchfeature_device` and `input_device_31_0` rules under SELinux Enforcing. |
| **Screen-Off FOD (SOFOD) freezes or doesn't wake** | `ro.vendor.mtk_aod_support` is not `0` on MTK panels without hardware AOD, or DT2W conflict | Set `ro.vendor.mtk_aod_support=0` in `vendor/build.prop`. For smooth DT2W + SOFOD coexistence, pair with [`coloros-dt2w-aidl-bridge`](https://github.com/DwiPrdn/coloros-dt2w-aidl-bridge) and [`coloros-r2w-aidl-bridge`](https://github.com/DwiPrdn/coloros-r2w-aidl-bridge). |
| **Enrolled fingerprints vanish after reboot** | `/data/vendor_de/0/fpdata_cos` creation/write failed under SELinux Enforcing or wrong ownership | Check `adb shell ls -ldZ /data/vendor_de/0/fpdata_cos` (must be `0770 system:system` and `u:object_r:vendor_fingerprint_data_file:s0`) and check `logcat -d \| grep avc:.*fpdata_cos`. |
| **SELinux Enforcing audit** | Missing CIL allow rule in `vendor_sepolicy.cil` / stale `precompiled_sepolicy` | Run `adb logcat -d \| grep -E "avc:.*hal_fingerprint_default"`. Remember Android `init` fast-loads `vendor/etc/selinux/precompiled_sepolicy` whenever `.sha256` files match — always recompile `precompiled_sepolicy` with `secilc` after editing `vendor_sepolicy.cil`! |

---

## License

MIT License — see [LICENSE](LICENSE).
