TARGET = tls_fixer
TITLE_ID = TLSF00001
OBJS = main.o font.o graphics.o

LIBS = -lSceCtrl_stub -lSceDisplay_stub -lScePower_stub -lSceVshBridge_stub

PREFIX = arm-vita-eabi
CC = $(PREFIX)-gcc
CFLAGS = -Wl,-q -Wall -Wextra -Werror -O3 -std=gnu11
ASFLAGS = $(CFLAGS)

BUILD_DIR ?= build
VITA_TOOLCHAIN = $(VITASDK)/share/vita.toolchain.cmake
KERNEL_MODULE = $(BUILD_DIR)/kernel/tls_fixer.skprx
DNS_FIX_MODULE = $(BUILD_DIR)/old_dns_fix/old_dns_fix.suprx
TLS13_PROVIDER = $(BUILD_DIR)/tls13-vita/provider/tls_fixer_http.suprx
BROWSER_PROVIDER = $(BUILD_DIR)/tls13-vita/browser/tls_fixer.suprx
MBEDTLS_ARCHIVE ?= $(CURDIR)/build/deps/mbedtls-4.2.0.tar.bz2
TLS13_SOURCES = $(shell find tls13 -type f -not -path '*/build/*' -not -path '*/__pycache__/*')
LICENSE_FILES = licenses/Mbed-TLS-LICENSE.txt licenses/TF-PSA-Crypto-LICENSE.txt licenses/mldsa-native-LICENSE.txt
PACKAGE_ASSETS = misc/compat.suprx misc/lhttp.suprx misc/lssl.suprx misc/comm2.suprx misc/certs.cer \
	sce_sys/icon0.png sce_sys/livearea/contents/bg.png sce_sys/livearea/contents/template.xml

all: $(TARGET).vpk

$(TARGET).vpk: eboot.bin $(KERNEL_MODULE) $(DNS_FIX_MODULE) $(TLS13_PROVIDER) $(BROWSER_PROVIDER) \
        THIRD_PARTY_NOTICES.md $(LICENSE_FILES) $(PACKAGE_ASSETS)
	vita-mksfoex -s TITLE_ID=$(TITLE_ID) "tls_fixer" param.sfo
	vita-pack-vpk -s param.sfo -b eboot.bin \
		-a sce_sys/icon0.png=sce_sys/icon0.png \
		-a sce_sys/livearea/contents/bg.png=sce_sys/livearea/contents/bg.png \
		-a sce_sys/livearea/contents/template.xml=sce_sys/livearea/contents/template.xml \
		-a $(KERNEL_MODULE)=tls_fixer.skprx \
		-a $(DNS_FIX_MODULE)=dnsfix.suprx \
		-a misc/compat.suprx=compat.suprx \
		-a misc/lhttp.suprx=lhttp.suprx \
		-a misc/lssl.suprx=lssl.suprx \
		-a $(TLS13_PROVIDER)=tls_fixer_http.suprx \
		-a $(BROWSER_PROVIDER)=tls_fixer.suprx \
		-a misc/comm2.suprx=comm2.suprx \
		-a THIRD_PARTY_NOTICES.md=THIRD_PARTY_NOTICES.md \
		-a licenses/Mbed-TLS-LICENSE.txt=licenses/Mbed-TLS-LICENSE.txt \
		-a licenses/TF-PSA-Crypto-LICENSE.txt=licenses/TF-PSA-Crypto-LICENSE.txt \
		-a licenses/mldsa-native-LICENSE.txt=licenses/mldsa-native-LICENSE.txt \
		-a misc/certs.cer=certs.cer $@

$(KERNEL_MODULE): kernel/main.c kernel/self_disarm.c kernel/self_disarm.h kernel/hook_guard.c kernel/hook_guard.h kernel/tls13_loader.c kernel/tls13_loader.h kernel/tls_fixer.yml kernel/CMakeLists.txt tools/verify_kernel_registers.py tls13/src/path.c tls13/include/tls_fixer/path.h tls13/include/tls_fixer/sony_abi.h tls13/include/tls_fixer/browser_abi.h
	cmake -S kernel -B $(BUILD_DIR)/kernel
	cmake --build $(BUILD_DIR)/kernel --clean-first

$(DNS_FIX_MODULE): old_dns_fix/main.c old_dns_fix/CMakeLists.txt old_dns_fix/exports.yml
	cmake -S old_dns_fix -B $(BUILD_DIR)/old_dns_fix -DCMAKE_TOOLCHAIN_FILE=$(VITA_TOOLCHAIN)
	cmake --build $(BUILD_DIR)/old_dns_fix --clean-first

$(MBEDTLS_ARCHIVE):
	@echo "Missing Mbed TLS archive. Run python3 tools/fetch_mbedtls.py on the host first." >&2
	@exit 1

$(TLS13_PROVIDER): $(TLS13_SOURCES) $(MBEDTLS_ARCHIVE)
	cmake -S tls13 -B $(BUILD_DIR)/tls13-vita \
		-DTLS_FIXER_BUILD_VITA_PROVIDER=ON \
		-DTLS_FIXER_MBEDTLS_ARCHIVE=$(MBEDTLS_ARCHIVE) \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_TOOLCHAIN_FILE=$(VITA_TOOLCHAIN)
	cmake --build $(BUILD_DIR)/tls13-vita --clean-first

$(BROWSER_PROVIDER): $(TLS13_PROVIDER)
	cmake --build $(BUILD_DIR)/tls13-vita --target tls_fixer.suprx-self

eboot.bin: $(TARGET).velf
	vita-make-fself -c $< $@

%.velf: %.elf
	vita-elf-create $< $@

$(TARGET).elf: $(OBJS)
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@

%.o: %.png
	$(PREFIX)-ld -r -b binary -o $@ $^

clean:
	rm -rf $(TARGET).vpk $(TARGET).velf $(TARGET).elf $(OBJS) \
		eboot.bin param.sfo $(BUILD_DIR)/kernel $(BUILD_DIR)/old_dns_fix \
		$(BUILD_DIR)/tls13-vita

.PHONY: all clean
