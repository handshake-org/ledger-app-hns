ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

APPNAME = "Handshake"

APPVERSION_M = 0
APPVERSION_N = 1
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

MAX_ADPU_INPUT_SIZE=217
MAX_ADPU_OUTPUT_SIZE=98

DEFINES   += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES   += HAVE_BAGL HAVE_SPRINTF
DEFINES   += HAVE_PRINTF PRINTF=screen_printf
# DEFINES   += PRINTF\(...\)=
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6
DEFINES   += IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES   += HNS_APP_MAJOR_VERSION=$(APPVERSION_M)
DEFINES   += HNS_APP_MINOR_VERSION=$(APPVERSION_N)
DEFINES   += HNS_APP_PATCH_VERSION=$(APPVERSION_P)
DEFINES   += MAX_ADPU_OUTPUT_SIZE=$(MAX_ADPU_OUTPUT_SIZE)
DEFINES   += CX_COMPLIANCE_141

# U2F
DEFINES   += HAVE_IO_U2F
DEFINES   += U2F_PROXY_MAGIC=\"mRB\"
DEFINES   += USB_SEGMENT_SIZE=64
DEFINES   += BLE_SEGMENT_SIZE=32       # max MTU, min 20
DEFINES   += U2F_REQUEST_TIMEOUT=10000 # 10 seconds
DEFINES   += UNUSED\(x\)=\(void\)x
DEFINES   += APPVERSION=\"$(APPVERSION)\"

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
APP_SOURCE_PATH  += src vendor/blake2 vendor/bech32 vendor/base58
SDK_SOURCE_PATH  += lib_stusb lib_stusb_impl lib_u2f qrcode

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

docker:
	docker build --build-arg CACHE_BUST='$(shell date)' -f Dockerfile.build -t ledger-app-hns-build .
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
