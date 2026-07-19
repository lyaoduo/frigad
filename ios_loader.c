#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <os/log.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

#include <mach-o/dyld.h>

/*
 * These values may be overridden at compile time, for example:
 *   -DLOADER_WAIT_TIMEOUT_SECONDS=0
 *   -DLOADER_GADGET_FILENAME=\"MyGadget.dylib\"
 */
#ifndef LOADER_GADGET_FILENAME
#define LOADER_GADGET_FILENAME "frigad.dylib"
#endif

#ifndef LOADER_WAIT_TIMEOUT_SECONDS
#define LOADER_WAIT_TIMEOUT_SECONDS 600U
#endif

#ifndef LOADER_POLL_INTERVAL_MS
#define LOADER_POLL_INTERVAL_MS 250U
#endif

#ifndef LOADER_ATTACH_SETTLE_MS
#define LOADER_ATTACH_SETTLE_MS 1000U
#endif

#define LOADER_STATUS_LOG_INTERVAL_MS 30000U
#define LOADER_LOG_PREFIX "[FrigadLoader] "

static atomic_flag gadget_load_scheduled = ATOMIC_FLAG_INIT;
static void *gadget_handle;

/*
 * Return 1 if traced, 0 if not traced, and -1 if the kernel query failed.
 * Fully zero-initializing kinfo_proc is important because kernels are allowed
 * to return less data than the SDK's current structure size.
 */
static int debugger_state(int *error_code) {
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info = {0};
    size_t info_size = sizeof(info);
    int result;

    do {
        result = sysctl(mib, 4, &info, &info_size, NULL, 0);
    } while (result == -1 && errno == EINTR);

    if (result == -1) {
        if (error_code != NULL) {
            *error_code = errno;
        }
        return -1;
    }

    if (error_code != NULL) {
        *error_code = 0;
    }

    return (info.kp_proc.p_flag & P_TRACED) != 0 ? 1 : 0;
}

static void sleep_milliseconds(uint32_t milliseconds) {
    struct timespec remaining = {
        .tv_sec = (time_t)(milliseconds / 1000U),
        .tv_nsec = (long)(milliseconds % 1000U) * 1000000L,
    };

    while (nanosleep(&remaining, &remaining) == -1 && errno == EINTR) {
    }
}

static bool build_gadget_path(char *path, size_t path_capacity) {
    char executable_path[PATH_MAX];
    uint32_t executable_path_size = (uint32_t)sizeof(executable_path);

    if (_NSGetExecutablePath(executable_path, &executable_path_size) != 0) {
        os_log_with_type(
            OS_LOG_DEFAULT,
            OS_LOG_TYPE_ERROR,
            LOADER_LOG_PREFIX
            "executable path is too long (%{public}u bytes required)",
            (unsigned int)executable_path_size);
        return false;
    }

    char *last_separator = strrchr(executable_path, '/');
    if (last_separator == NULL) {
        os_log_with_type(OS_LOG_DEFAULT,
                         OS_LOG_TYPE_ERROR,
                         LOADER_LOG_PREFIX "unable to determine the app bundle path");
        return false;
    }
    *last_separator = '\0';

    int length = snprintf(path,
                          path_capacity,
                          "%s/Frameworks/%s",
                          executable_path,
                          LOADER_GADGET_FILENAME);
    if (length < 0 || (size_t)length >= path_capacity) {
        os_log_with_type(OS_LOG_DEFAULT,
                         OS_LOG_TYPE_ERROR,
                         LOADER_LOG_PREFIX "Gadget path exceeds PATH_MAX");
        return false;
    }

    return true;
}

/*
 * Loading on the main queue matches Gadget's normal dyld initialization
 * context and avoids initializing Darwin/Objective-C machinery on the polling
 * thread. The handle is intentionally retained for the lifetime of the app.
 */
static void load_gadget_on_main_queue(void *context) {
    (void)context;

    char gadget_path[PATH_MAX];
    if (!build_gadget_path(gadget_path, sizeof(gadget_path))) {
        return;
    }

    if (access(gadget_path, R_OK) != 0) {
        os_log_with_type(OS_LOG_DEFAULT,
                         OS_LOG_TYPE_ERROR,
                         LOADER_LOG_PREFIX
                         "Gadget is not readable at %{public}s: %{public}s",
                         gadget_path,
                         strerror(errno));
        return;
    }

    /* Preflight catches architecture, dependency, and signing errors without
       running Gadget's constructors. */
    (void)dlerror();
    if (dlopen_preflight(gadget_path) == 0) {
        const char *error_message = dlerror();
        os_log_with_type(OS_LOG_DEFAULT,
                         OS_LOG_TYPE_ERROR,
                         LOADER_LOG_PREFIX
                         "Gadget preflight failed for %{public}s: %{public}s",
                         gadget_path,
                         error_message != NULL ? error_message
                                               : "unknown dyld error");
        return;
    }

    os_log_with_type(OS_LOG_DEFAULT,
                     OS_LOG_TYPE_DEFAULT,
                     LOADER_LOG_PREFIX "loading Gadget from %{public}s",
                     gadget_path);

    (void)dlerror();
    gadget_handle = dlopen(gadget_path, RTLD_NOW | RTLD_LOCAL);
    if (gadget_handle == NULL) {
        const char *error_message = dlerror();
        os_log_with_type(OS_LOG_DEFAULT,
                         OS_LOG_TYPE_ERROR,
                         LOADER_LOG_PREFIX "Gadget load failed: %{public}s",
                         error_message != NULL ? error_message
                                               : "unknown dyld error");
        return;
    }

    os_log_with_type(OS_LOG_DEFAULT,
                     OS_LOG_TYPE_DEFAULT,
                     LOADER_LOG_PREFIX "Gadget loaded successfully");
}

static void *wait_for_debugger(void *context) {
    (void)context;

    const uint64_t timeout_ms = (uint64_t)LOADER_WAIT_TIMEOUT_SECONDS * 1000U;
    uint64_t elapsed_ms = 0;
    uint64_t next_status_log_ms = LOADER_STATUS_LOG_INTERVAL_MS;
    bool query_error_logged = false;

    if (LOADER_WAIT_TIMEOUT_SECONDS == 0U) {
        os_log_with_type(OS_LOG_DEFAULT,
                         OS_LOG_TYPE_DEFAULT,
                         LOADER_LOG_PREFIX "waiting for a debugger (no timeout)");
    } else {
        os_log_with_type(
            OS_LOG_DEFAULT,
            OS_LOG_TYPE_DEFAULT,
            LOADER_LOG_PREFIX
            "waiting up to %{public}u seconds for a debugger",
            (unsigned int)LOADER_WAIT_TIMEOUT_SECONDS);
    }

    while (timeout_ms == 0U || elapsed_ms < timeout_ms) {
        int error_code = 0;
        int state = debugger_state(&error_code);

        if (state == 1) {
            os_log_with_type(
                OS_LOG_DEFAULT,
                OS_LOG_TYPE_DEFAULT,
                LOADER_LOG_PREFIX
                "debugger detected; allowing %{public}u ms for attach to settle",
                (unsigned int)LOADER_ATTACH_SETTLE_MS);

            sleep_milliseconds(LOADER_ATTACH_SETTLE_MS);

            /* Confirm that the debugger is still attached before loading. */
            state = debugger_state(&error_code);
            if (state == 1) {
                if (!atomic_flag_test_and_set_explicit(&gadget_load_scheduled,
                                                       memory_order_acq_rel)) {
                    dispatch_async_f(dispatch_get_main_queue(),
                                     NULL,
                                     load_gadget_on_main_queue);
                }
                return NULL;
            }

            os_log_with_type(
                OS_LOG_DEFAULT,
                OS_LOG_TYPE_DEFAULT,
                LOADER_LOG_PREFIX
                "debugger detached before Gadget was scheduled");
        } else if (state == -1 && !query_error_logged) {
            os_log_with_type(OS_LOG_DEFAULT,
                             OS_LOG_TYPE_ERROR,
                             LOADER_LOG_PREFIX
                             "debugger query failed: %{public}s (%{public}d)",
                             strerror(error_code),
                             error_code);
            query_error_logged = true;
        }

        if (elapsed_ms >= next_status_log_ms) {
            os_log_with_type(
                OS_LOG_DEFAULT,
                OS_LOG_TYPE_DEFAULT,
                LOADER_LOG_PREFIX
                "still waiting for a debugger (%{public}llu seconds)",
                (unsigned long long)(elapsed_ms / 1000U));
            next_status_log_ms += LOADER_STATUS_LOG_INTERVAL_MS;
        }

        sleep_milliseconds(LOADER_POLL_INTERVAL_MS);
        elapsed_ms += LOADER_POLL_INTERVAL_MS;
    }

    os_log_with_type(OS_LOG_DEFAULT,
                     OS_LOG_TYPE_DEFAULT,
                     LOADER_LOG_PREFIX
                     "debugger wait timed out after %{public}u seconds",
                     (unsigned int)LOADER_WAIT_TIMEOUT_SECONDS);
    return NULL;
}

__attribute__((constructor)) static void initialize_loader(void) {
    pthread_attr_t attributes;
    pthread_t thread;

    int result = pthread_attr_init(&attributes);
    if (result != 0) {
        os_log_with_type(OS_LOG_DEFAULT,
                         OS_LOG_TYPE_ERROR,
                         LOADER_LOG_PREFIX
                         "pthread_attr_init failed: %{public}s (%{public}d)",
                         strerror(result),
                         result);
        return;
    }

    result = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    if (result == 0) {
        result = pthread_create(&thread, &attributes, wait_for_debugger, NULL);
    }

    (void)pthread_attr_destroy(&attributes);

    if (result != 0) {
        os_log_with_type(OS_LOG_DEFAULT,
                         OS_LOG_TYPE_ERROR,
                         LOADER_LOG_PREFIX
                         "unable to start debugger monitor: %{public}s (%{public}d)",
                         strerror(result),
                         result);
    }
}
