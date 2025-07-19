TARGET := iphone:clang:latest:latest
ARCHS = arm64
DEBUG = 0
FINALPACKAGE = 1
FOR_RELEASE = 1

# Change to your own $THEOS path, or remove if env is already set. I had a shell issue :/
THEOS = /home/rage/theos

SYSROOT = $(THEOS)/sdks/iPhoneOS13.7.sdk
# AGAIN i had fucking SDK issues...
# had to downgrade to 13.7
include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = libtitanox

# Srcs
#Capstone_FILES = \
    decoder/capstone/cs.c \
    $(wildcard decoder/capstone/arch/AArch64/*.c) \
    $(filter-out decoder/capstone/cs.c, $(wildcard decoder/capstone/*.c))
	
FISHHOOK_FILES := $(wildcard Fishhook/*.c)
BRK_HOOK_FILES := $(wildcard BreakpointHook/Hook/*.c)
MEMPATCH_FILES := $(wildcard MemPatch/*.cpp)
UTILS_FILES := $(wildcard Utils/*.cpp)
MAIN_SRCS := $(wildcard Libtitanox/*.cpp)
VM_FILES := $(wildcard VM_Funcs/*.cpp)
MEMX_FILES := $(wildcard MemX/*.cpp)
SIH_FILES := $(wildcard Static-Inline-Hook/*.cpp)
DISASM_FILES := $(wildcard decoder/*.cpp)

$(LIBRARY_NAME)_FILES = $(SIH_FILES) $(MEMX_FILES) $(BRK_HOOK_FILES) $(VM_FILES) $(UTILS_FILES) $(FISHHOOK_FILES) $(MAIN_SRCS) $(MEMPATCH_FILES)
$(LIBRARY_NAME)_CFLAGS = -fobjc-arc -Wall -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-value -Wno-unused-function -Idecoder/. -Idecoder/capstone -Idecoder/capstone/include

$(LIBRARY_NAME)_CCFLAGS = -x objective-c++ -std=c++17 -fno-rtti -DNDEBUG -Wall -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-value -Wno-unused-function -Idecoder/. -Idecoder/capstone -Idecoder/capstone/include 
#$(LIBRARY_NAME)_LDFLAGS = -L./Frameworks/capstone/


# you could change this to @rpath
$(LIBRARY_NAME)_INSTALL_PATH = @executable_path
$(LIBRARY_NAME)_FRAMEWORKS = Foundation CoreFoundation

include $(THEOS_MAKE_PATH)/library.mk

# Remove all this if you want. This basically just gives me my dylib extracted from the .deb.
after-package::
	@echo -e "\033[0;33m==> Copying libtitanox.dylib to packages directory...\033[0m"
	@timeout 2 cp /home/rage/theos/lib/libtitanox.dylib ./packages/
	@echo -e "\033[0;32m==> Copy complete.\033[0m"

	@echo -e "\033[0;33m==> Removing .deb file from packages...\033[0m"
	@rm -f packages/*.deb
	@echo -e "\033[0;32m==> .deb file removed.\033[0m"