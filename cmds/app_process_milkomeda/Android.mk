LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    app_main_milkomeda.cpp \
    shield.cpp

LOCAL_LDFLAGS := -Wl,--version-script,art/sigchainlib/version-script.txt -Wl,--export-dynamic

LOCAL_SHARED_LIBRARIES := \
    libdl \
    libcutils \
    libutils \
    liblog \
    libbinder \
    libnativeloader \
    libandroid_runtime \
    libGLESv2 \
    $(app_process_milkomeda_common_shared_libs) \

LOCAL_WHOLE_STATIC_LIBRARIES := libsigchain

LOCAL_MODULE:= app_process_milkomeda
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := app_process_milkomeda32
LOCAL_MODULE_STEM_64 := app_process_milkomeda64

LOCAL_CFLAGS += -Wall -Werror -Wunused -Wunreachable-code

include $(BUILD_EXECUTABLE)

include  $(BUILD_SYSTEM)/executable_prefer_symlink.mk

ifeq ($(TARGET_ARCH),arm)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    app_main_milkomeda.cpp \
    shield.cpp

LOCAL_SHARED_LIBRARIES := \
    libcutils \
    libutils \
    liblog \
    libbinder \
    libandroid_runtime \
    libGLESv2 \
    $(app_process_milkomeda_common_shared_libs) \

LOCAL_WHOLE_STATIC_LIBRARIES := libsigchain

LOCAL_LDFLAGS := -ldl -Wl,--version-script,art/sigchainlib/version-script.txt -Wl,--export-dynamic
LOCAL_CPPFLAGS := -std=c++11

LOCAL_MODULE := app_process_milkomeda__asan
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := app_process_milkomeda32
LOCAL_MODULE_STEM_64 := app_process_milkomeda64

LOCAL_SANITIZE := address
LOCAL_CLANG := true
LOCAL_MODULE_PATH := $(TARGET_OUT_EXECUTABLES)/asan

LOCAL_CFLAGS += -Wall -Werror -Wunused -Wunreachable-code

include $(BUILD_EXECUTABLE)
endif # ifeq($(TARGET_ARCH),arm)
