
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := dhcp-helper.c
LOCAL_CFLAGS := -DVERSION=\"1.3-android\"
# TODO: put git revision/version in there somehow

LOCAL_MODULE = dhcp-helper
include $(BUILD_EXECUTABLE)
