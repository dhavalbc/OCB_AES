LOCAL_PATH := $(call my-dir)

$(call import-add-path,$(LOCAL_PATH)/libs)

include $(CLEAR_VARS)
LOCAL_CFLAGS += -Wall -Werror
LOCAL_CPP_EXTENSION := .cc
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS = -Wno-unused-parameter -fexceptions
LOCAL_C_INCLUDES := \
        external/ocb_aes/include/ \
        external/boringssl/include

EXAMPLE_SRC_FILES := src/main.cc \
                     src/CryptState.cc \
                     src/Timer.cc

LOCAL_SRC_FILES := $(EXAMPLE_SRC_FILES)
LOCAL_SHARED_LIBRARIES += libssl liblog libcrypto
#LOCAL_SHARED_LIBRARIES += libcrypto libssl
LOCAL_MODULE := ocb_aes_test
LOCAL_MODULE_PATH := $(TARGET_OUT_EXECUTABLES)
include $(BUILD_EXECUTABLE)