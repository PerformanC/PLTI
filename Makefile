NDK_PATH ?= $(HOME)/Android/Sdk/ndk/29.0.13113456
API_LEVEL ?= 26
ARCH ?= arm64-v8a

TOOLCHAIN = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64
SYSROOT = $(TOOLCHAIN)/sysroot
CC = $(TOOLCHAIN)/bin/clang
AR = $(TOOLCHAIN)/bin/llvm-ar

TARGET_arm64-v8a = aarch64-linux-android$(API_LEVEL)
TARGET_armeabi-v7a = armv7a-linux-androideabi$(API_LEVEL)
TARGET_x86 = i686-linux-android$(API_LEVEL)
TARGET_x86_64 = x86_64-linux-android$(API_LEVEL)

CC_ARCH = $(CC) --target=$(TARGET_$(ARCH)) --sysroot=$(SYSROOT)

CFLAGS_BASE = -std=c99 -DANDROID -fPIC -Isrc -Wpedantic -Wall -Wextra -Werror -Wformat -Wuninitialized -Wshadow -Wno-variadic-macros

CFLAGS_debug = $(CFLAGS_BASE) -g -O0 -DPLTI_LOGGING
CFLAGS_release = $(CFLAGS_BASE) -O3 -flto

BUILD_TYPE ?= debug
out ?= build/$(BUILD_TYPE)/$(ARCH)

CFLAGS = $(CFLAGS_$(BUILD_TYPE))

SRCS = src/plti.c src/elf_util.c
OBJS = $(patsubst src/%.c,$(out)/%.o,$(SRCS))
DEPS = $(OBJS:.o=.d)
STATIC_LIB = $(out)/libplti.a
SHARED_LIB = $(out)/libplti.so

.PHONY: all lib_debug lib_release clean

all: $(STATIC_LIB) $(SHARED_LIB)

lib_debug:
	$(MAKE) BUILD_TYPE=debug out=build/debug/$(ARCH) all

lib_release:
	$(MAKE) BUILD_TYPE=release out=build/release/$(ARCH) all

$(out)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(CFLAGS) -c $< -o $@

$(STATIC_LIB): $(OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(SHARED_LIB): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(CFLAGS) -shared -Wl,-soname,libplti.so $(OBJS) -llog -ldl -o $@

-include $(DEPS)

clean:
	rm -rf build
