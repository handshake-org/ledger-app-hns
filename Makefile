ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

APPNAME = "Handshake"

APPVERSION_M = 1
APPVERSION_N = 0
APPVERSION_P = 0
APPVERSION = $(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)

APP_LOAD_FLAGS = --appFlags 0x50
APP_PATH_PARAMS = --path ""
APP_LOAD_PARAMS = --curve secp256k1 $(COMMON_LOAD_PARAMS)
APP_LOAD_PARAMS += $(APP_LOAD_FLAGS) $(APP_PATH_PARAMS)

ICONNAME=nanos_icon_hns.gif

################
# Default rule #
################

all: default

############
# Platform #
############

# DEFINES   += HAVE_BOLOS_APP_STACK_CANARY
DEFINES   += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES   += HAVE_BAGL HAVE_SPRINTF
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6
DEFINES   += IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES   += HNS_APP_MAJOR_VERSION=$(APPVERSION_M)
DEFINES   += HNS_APP_MINOR_VERSION=$(APPVERSION_N)
DEFINES   += HNS_APP_PATCH_VERSION=$(APPVERSION_P)
DEFINES   += CX_COMPLIANCE_141
DEFINES   += UNUSED\(x\)=\(void\)x
DEFINES   += APPVERSION=\"$(APPVERSION)\"
DEFINES   += BLAKE_SDK

# U2F
DEFINES   += HAVE_U2F HAVE_IO_U2F
DEFINES   += U2F_PROXY_MAGIC=\"HNS\"
DEFINES   += USB_SEGMENT_SIZE=64
DEFINES   += BLE_SEGMENT_SIZE=32 # max MTU, min 20

# WebUSB
WEBUSB_URL     = www.handshake.org
DEFINES       += HAVE_WEBUSB
DEFINES       += WEBUSB_URL_SIZE_B=$(shell echo -n $(WEBUSB_URL) | wc -c)
DEFINES       += WEBUSB_URL=$(shell echo -n $(WEBUSB_URL) | sed -e "s/./\\\'\0\\\',/g")

# PRINTF (must have debug enabled firmware)
DEBUG = 0
ifneq ($(DEBUG),0)
	DEFINES   += HAVE_PRINTF PRINTF=screen_printf
else
	DEFINES   += PRINTF\(...\)=
endif

##############
# Compiler #
##############
ifneq ($(BOLOS_ENV),)
$(info BOLOS_ENV=$(BOLOS_ENV))
CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
GCCPATH := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
else
$(info BOLOS_ENV is not set: falling back to CLANGPATH and GCCPATH)
endif
ifeq ($(CLANGPATH),)
$(info CLANGPATH is not set: clang will be used from PATH)
endif
ifeq ($(GCCPATH),)
$(info GCCPATH is not set: arm-none-eabi-* will be used from PATH)
endif

CC       := $(CLANGPATH)clang

CFLAGS   += -O3 -Os -Wno-typedef-redefinition

AS       := $(GCCPATH)arm-none-eabi-gcc

LD       := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS  += -O3 -Os
LDLIBS   += -lm -lgcc -lc

# import rules to compile glyphs(/pone)
include $(BOLOS_SDK)/Makefile.glyphs

### variables processed by the common makefile.rules
### of the SDK to grab source files and include dirs
APP_SOURCE_PATH  += src vendor/bech32 vendor/base58
SDK_SOURCE_PATH  += lib_stusb lib_stusb_impl lib_u2f qrcode

# SDK build target
ifeq ($(GIT_REF),)
GIT_REF := og-1.6.0-1
else
$(info GIT_REF is set to $(GIT_REF))
endif

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

docker:
	docker build --build-arg GIT_REF='$(shell echo $(GIT_REF))' --build-arg CACHE_BUST='$(shell date)' -f Dockerfile.build -t ledger-app-hns-build .
	docker run --name ledger-app-hns-build ledger-app-hns-build
	docker cp ledger-app-hns-build:/ledger-app-hns/bin/app.elf ./bin
	docker cp ledger-app-hns-build:/ledger-app-hns/bin/app.hex ./bin
	docker cp ledger-app-hns-build:/ledger-app-hns/debug/app.map ./debug
	docker cp ledger-app-hns-build:/ledger-app-hns/debug/app.asm ./debug
	docker rm ledger-app-hns-build

docker-load: docker
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

# do not run additional goals when using docker
MAKECMDGOALS := docker docker-load

# import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

# add dependency on custom makefile filename
dep/%.d: %.c Makefile

.PHONY: load delete docker docker-load
