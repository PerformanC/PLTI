#ifndef PLTI_LOGGING_H
#define PLTI_LOGGING_H

#include <android/log.h>

#if 1
    #define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "PLTI", __VA_ARGS__)
    #define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "PLTI", __VA_ARGS__)
    #define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  "PLTI", __VA_ARGS__)
    #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "PLTI", __VA_ARGS__)
    #define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, "PLTI", __VA_ARGS__)
    #define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))
#else
    #define LOGI(...) ((void)0)
    #define LOGD(...) ((void)0)
    #define LOGW(...) ((void)0)
    #define LOGE(...) ((void)0)
    #define LOGF(...) ((void)0)
    #define PLOGE(fmt, args...) ((void)0)
#endif

#endif /* PLTI_LOGGING_H */
