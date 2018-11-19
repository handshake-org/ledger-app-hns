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

ifeq ($(TARGET_NAME),TARGET_BLUE)
ICONNAME=blue_icon_hns.gif
else
ICONNAME=nanos_icon_hns.gif
endif

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
# DEFINES   += HAVE_PRINTF PRINTF=screen_printf
DEFINES   += PRINTF\(...\)=
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

############
# Compiler #
############
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
APP_SOURCE_PATH  += src vendor/blake2 vendor/bech32
SDK_SOURCE_PATH  += lib_stusb
SDK_SOURCE_PATH  += lib_stusb_impl
SDK_SOURCE_PATH  += lib_u2f

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

# import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

# add dependency on custom makefile filename
dep/%.d: %.c Makefile

