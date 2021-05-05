ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

#
# Version
#

MAJOR = 1
MINOR = 0
PATCH = 4

#
# App
#

APPNAME = "Handshake"
ICONNAME = nanos_icon_hns.gif
APPVERSION = $(MAJOR).$(MINOR).$(PATCH)

APP_LOAD_PARAMS = --appFlags 0xa50 --path "" --curve secp256k1 \
                  $(COMMON_LOAD_PARAMS)
APP_SOURCE_PATH = src vendor/bech32 vendor/base58
SDK_SOURCE_PATH = lib_stusb lib_stusb_impl lib_u2f qrcode

ifeq ($(TARGET_NAME),TARGET_NANOX)
SDK_SOURCE_PATH += lib_blewbxx lib_blewbxx_impl lib_ux
ICONNAME = nanox_icon_hns.gif
endif

# Ledger maintainers put these here.
# APP_LOAD_PARAMS += --tlvraw 9F:01
# DEFINES += HAVE_PENDING_REVIEW_SCREEN

#
# Platform
#

DEFINES += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES += HAVE_BAGL HAVE_SPRINTF HAVE_SNPRINTF_FORMAT_U
DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=4
DEFINES += IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES += TCS_LOADER_PATCH_VERSION=0
DEFINES += HNS_APP_MAJOR_VERSION=$(MAJOR)
DEFINES += HNS_APP_MINOR_VERSION=$(MINOR)
DEFINES += HNS_APP_PATCH_VERSION=$(PATCH)
DEFINES += UNUSED\(x\)=\(void\)x
DEFINES += APPVERSION=\"$(APPVERSION)\"
DEFINES += BLAKE_SDK

# U2F
DEFINES += HAVE_U2F HAVE_IO_U2F
DEFINES += U2F_PROXY_MAGIC=\"HNS\"
DEFINES += USB_SEGMENT_SIZE=64
DEFINES += BLE_SEGMENT_SIZE=32

# WebUSB
DEFINES += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""

ifeq ($(TARGET_NAME),TARGET_NANOX)
DEFINES += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000
DEFINES += HAVE_BLE_APDU
DEFINES += HAVE_UX_FLOW

DEFINES += HAVE_GLO096
DEFINES += HAVE_BAGL BAGL_WIDTH=128 BAGL_HEIGHT=64
DEFINES += HAVE_BAGL_ELLIPSIS
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
endif

#
# Detect Flow Support for Nano S
# (currently disabled due to memory consumption)
#

#ifneq ($(TARGET_NAME),TARGET_NANOX)
#ifneq ("$(wildcard $(BOLOS_SDK)/lib_ux/include/ux_flow_engine.h)","")
#DEFINES += HAVE_UX_FLOW
#SDK_SOURCE_PATH += lib_ux
#endif
#endif

#
# Debugging
#

DEBUG := 0
ifneq ($(DEBUG),0)
ifeq ($(TARGET_NAME),TARGET_NANOX)
DEFINES += HAVE_PRINTF PRINTF=mcu_usb_printf
else
DEFINES += HAVE_PRINTF PRINTF=screen_printf
endif
else
DEFINES += PRINTF\(...\)=
endif

#
# Compiler
#

ifneq ($(BOLOS_ENV),)
CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
GCCPATH := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
endif

CC := $(CLANGPATH)clang
AS := $(GCCPATH)arm-none-eabi-gcc
LD := $(GCCPATH)arm-none-eabi-gcc

CFLAGS += -O3 -Os
CFLAGS += -Wno-typedef-redefinition
CFLAGS += -Wno-incompatible-pointer-types-discards-qualifiers
CFLAGS += -I/usr/include/
LDFLAGS += -O3 -Os
LDLIBS += -lm -lgcc -lc

#
# Rules
#

all: default

include $(BOLOS_SDK)/Makefile.glyphs

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

include $(BOLOS_SDK)/Makefile.rules

dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS COIN hns

#
# Docker Rules
#

ifeq ($(GIT_NAME),)
GIT_NAME := nanos-secure-sdk
endif

ifeq ($(GIT_REF),)
GIT_REF := nanos-1612
endif

DOCKER_ARGS = --build-arg GIT_NAME='$(GIT_NAME)'     \
              --build-arg GIT_REF='$(GIT_REF)'       \
              --build-arg CACHE_BUST='$(shell date)'

docker:
	docker build $(DOCKER_ARGS) -f Dockerfile.build -t ledger-app-hns-build .
	docker run --name ledger-app-hns-build ledger-app-hns-build
	docker cp ledger-app-hns-build:/ledger-app-hns/bin/app.elf ./bin
	docker cp ledger-app-hns-build:/ledger-app-hns/bin/app.hex ./bin
	docker cp ledger-app-hns-build:/ledger-app-hns/debug/app.map ./debug
	docker cp ledger-app-hns-build:/ledger-app-hns/debug/app.asm ./debug
	docker rm ledger-app-hns-build

docker-load: docker
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

docker-build-all:
	docker build -f Dockerfile.build-all -t ledger-app-hns-build-all . --progress=plain
	docker run --name ledger-app-hns-build-all ledger-app-hns-build-all
	docker cp ledger-app-hns-build-all:/nanos/bin/app.elf ./bin/hns-nanos.elf
	docker cp ledger-app-hns-build-all:/nanos/bin/app.hex ./bin/hns-nanos.hex
	docker cp ledger-app-hns-build-all:/nanos/debug/app.map ./debug/hns-nanos.map
	docker cp ledger-app-hns-build-all:/nanos/debug/app.asm ./debug/hns-nanos.asm
	docker cp ledger-app-hns-build-all:/nanox/bin/app.elf ./bin/hns-nanox.elf
	docker cp ledger-app-hns-build-all:/nanox/bin/app.hex ./bin/hns-nanox.hex
	docker cp ledger-app-hns-build-all:/nanox/debug/app.map ./debug/hns-nanox.map
	docker cp ledger-app-hns-build-all:/nanox/debug/app.asm ./debug/hns-nanox.asm
	docker rm ledger-app-hns-build-all

MAKECMDGOALS := docker docker-load

.PHONY: all load delete listvariants docker docker-load
