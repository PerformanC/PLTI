# Builds a test for the replacement of the GOT's VMA and runs it on a connected Android device.
#
#   make                       build
#   make run                   hook, once
#   make run-unhook            hook and remove it, once
#   make survive N=200         count the runs that got through the hook
#   make survive-unhook N=200  count the runs that got through the hook and its removal
#
# A run is one process, and survives when it exits normally. "make run" and "make run-unhook"
# print how the GOT is mapped at each step.
#
# SRC=apk      load the library from an APK instead of a file
# UNLINK=1     delete the library file after loading it, so PLTI cannot read it back
#
# NDK: directory of the NDK to use (defaults to the newest one in the Android SDK).
# SDK: directory of the Android SDK, for zipalign, which SRC=apk needs.
# PLTI_EXTRA_FLAGS: added when compiling PLTI, e.g. -DPLTI_LOGGING to have it log to logcat.

NDK ?= $(firstword $(sort $(wildcard $(HOME)/Library/Android/sdk/ndk/*) $(wildcard $(HOME)/Android/Sdk/ndk/*)))
API ?= 29
ARCH ?= arm64-v8a
N ?= 200
SRC ?= file
UNLINK ?= 0
SDK ?= $(if $(wildcard $(HOME)/Library/Android/sdk),$(HOME)/Library/Android/sdk,$(HOME)/Android/Sdk)
ZIPALIGN ?= $(firstword $(sort $(wildcard $(SDK)/build-tools/*/zipalign)))
DIR_ON_DEVICE ?= /data/local/tmp/plti-got-race

ifeq ($(ARCH),arm64-v8a)
  TRIPLE := aarch64-linux-android
else ifeq ($(ARCH),x86_64)
  TRIPLE := x86_64-linux-android
else
  $(error unsupported ARCH $(ARCH))
endif

TOOLCHAIN := $(NDK)/toolchains/llvm/prebuilt/darwin-x86_64/bin
ifeq ($(wildcard $(TOOLCHAIN)),)
  TOOLCHAIN := $(NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin
endif
CC := $(TOOLCHAIN)/$(TRIPLE)$(API)-clang

CFLAGS := -std=c99 -DANDROID -fPIC -I../../src -O2 -Wall -Wextra
LDFLAGS := -Wl,-z,relro -Wl,-z,now -Wl,--no-undefined

out := build/$(ARCH)
binaries := $(out)/libvictim.so $(out)/libhook.so $(out)/target
ifeq ($(SRC),apk)
  binaries += $(out)/test.apk
  victim := $(DIR_ON_DEVICE)/test.apk!/lib/$(ARCH)/libvictim.so
else ifeq ($(UNLINK),1)
  victim := $(DIR_ON_DEVICE)/unlink/libvictim.so
else
  victim := $(DIR_ON_DEVICE)/libvictim.so
endif
victim_env := VICTIM='$(victim)'$(if $(filter 1,$(UNLINK)), PLTI_GOT_RACE_UNLINK=1)
PLTI_OBJECTS := $(out)/plti.o $(out)/elf_util.o

.PHONY: all run run-unhook survive survive-unhook clean push
.SUFFIXES:

all: $(binaries)

$(out)/%.o: %.c | $(out)
	$(CC) $(CFLAGS) -c -o $@ $<

$(PLTI_OBJECTS): $(out)/%.o: ../../src/%.c ../../src/plti.h ../../src/elf_util.h ../../src/logging.h | $(out)
	$(CC) $(CFLAGS) $(PLTI_EXTRA_FLAGS) -Wpedantic -Wformat -Wuninitialized -Wshadow -Werror -Wno-variadic-macros -c -o $@ $<

# The library needs full RELRO, which puts its GOT in the read-only mapping PLTI has to replace.
$(out)/libvictim.so: $(out)/victim.o | $(out)
	$(CC) -shared -o $@ $< $(LDFLAGS)

$(out)/libhook.so: $(out)/hook.o $(PLTI_OBJECTS) | $(out)
	$(CC) -shared -o $@ $^ $(LDFLAGS) -llog

$(out)/target: $(out)/target.o | $(out)
	$(CC) -o $@ $< $(LDFLAGS) -ldl

# The dynamic linker only maps an entry of an APK that is stored and page-aligned.
$(out)/test.apk: $(out)/libvictim.so | $(out)
	@test -n "$(ZIPALIGN)" || { echo "zipalign was not found under $(SDK)/build-tools: set SDK"; exit 1; }
	rm -rf $(out)/apk
	mkdir -p $(out)/apk/lib/$(ARCH)
	cp $< $(out)/apk/lib/$(ARCH)/
	cd $(out)/apk && zip -q -0 -r ../test-unaligned.apk lib
	$(ZIPALIGN) -f -p 4096 $(out)/test-unaligned.apk $@

$(out):
	mkdir -p $(out)

push: all
	adb shell "mkdir -p $(DIR_ON_DEVICE)"
	adb push $(binaries) count.sh $(DIR_ON_DEVICE)/ > /dev/null

run run-unhook: push
	@adb shell "cd $(DIR_ON_DEVICE) && $(if $(filter 1,$(UNLINK)),mkdir -p unlink && cp libvictim.so unlink/libvictim.so && ,)$(victim_env) PLTI_GOT_RACE_DEBUG=1 LD_LIBRARY_PATH=. ./target $(if $(filter run-unhook,$@),unhook); echo exit=\$$?"

survive survive-unhook: push
	@adb shell "cd $(DIR_ON_DEVICE) && $(victim_env) LD_LIBRARY_PATH=. sh count.sh $(N) $(if $(filter 1,$(UNLINK)),unlink) $(if $(filter survive-unhook,$@),unhook)"

clean:
	rm -rf build
