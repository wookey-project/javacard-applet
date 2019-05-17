THIS_FILE := $(lastword $(MAKEFILE_LIST))
SILENT_MAKE := $(MAKE) --no-print-directory
PROJ_FILES=../
include ../m_config.mk

APPLET_PATH=$(PROJ_FILES)/javacard/applet/
APPLET_SRC_PATH=$(APPLET_PATH)/src

all: applets

applet_auth:
	rm -rf $(APPLET_SRC_PATH)/wookey/tmp/
	mkdir -p $(APPLET_SRC_PATH)/wookey/tmp/
	# Auth
	cp -r $(APPLET_SRC_PATH)/wookey/common $(APPLET_SRC_PATH)/wookey/tmp/common_auth
	sed -i '1 i\package wookey_auth;' $(APPLET_SRC_PATH)/wookey/tmp/common_auth/*.java
	cp $(KEYS_DIR)/AUTH/AUTHKeys.java $(APPLET_SRC_PATH)/wookey/tmp/common_auth/Keys.java
	cd $(APPLET_PATH) && ant build_auth;
	rm -rf $(APPLET_SRC_PATH)/wookey/tmp/

applet_dfu:
	rm -rf  $(APPLET_SRC_PATH)/wookey/tmp/
	mkdir -p  $(APPLET_SRC_PATH)/wookey/tmp/
	# DFU
	cp -r  $(APPLET_SRC_PATH)/wookey/common  $(APPLET_SRC_PATH)/wookey/tmp/common_dfu
	sed -i '1 i\package wookey_dfu;'  $(APPLET_SRC_PATH)/wookey/tmp/common_dfu/*.java
	cp $(KEYS_DIR)/DFU/DFUKeys.java $(APPLET_SRC_PATH)/wookey/tmp/common_dfu/Keys.java
	cd $(APPLET_PATH) && ant build_dfu;
	rm -rf $(APPLET_SRC_PATH)/wookey/tmp/

applet_sig:
	rm -rf $(APPLET_SRC_PATH)/wookey/tmp/
	mkdir -p $(APPLET_SRC_PATH)/wookey/tmp/
	# SIG
	# NOTE: SIG token being optional, we check for the need to compile it
	if [ -f $(KEYS_DIR)/SIG/SIGKeys.java ]; then \
		cp -r $(APPLET_SRC_PATH)/wookey/common $(APPLET_SRC_PATH)/wookey/tmp/common_sig; \
		sed -i '1 i\package wookey_sig;' $(APPLET_SRC_PATH)/wookey/tmp/common_sig/*java; \
		cp $(KEYS_DIR)/SIG/SIGKeys.java $(APPLET_SRC_PATH)/wookey/tmp/common_sig/Keys.java; \
		cd $(APPLET_PATH) && ant build_sig; \
	fi;
	rm -rf $(APPLET_SRC_PATH)/wookey/tmp/


applets: applet_auth applet_dfu applet_sig

clean_applets:
	cd applet && ant clean

clean: clean_applets

push_auth:
	@CHECK_CARD=`java -jar $(APPLET_PATH)/gp.jar -i 2>/dev/null | grep ATR`; \
	while [ "$$CHECK_CARD" = "" ]; do \
		echo -n "\r\033[1;41m No token detected. Please insert your AUTH token (waiting) ...\033[1;m"; \
		CHECK_CARD=`java -jar $(APPLET_PATH)/gp.jar -i 2>/dev/null | grep ATR`; \
		sleep 1; \
	done;
ifeq ("$(USE_DIFFERENT_PHYSICAL_TOKENS)","y")
	@# Check that we do not have another token here ...
	@CHECK_DFU=`java -jar $(APPLET_PATH)/gp.jar -l 2>/dev/null | grep 45757477747536417071 | grep Applet`; \
	if [ "$$CHECK_DFU" != "" ]; then \
		echo -n "\r\033[1;41m Error: you have inserted a smartcard already programmed with a DFU applet, but you have asked to use one smartcard per token."; \
		echo -n "Please insert a virgin token, or purge the current one!\033[1;m"; \
		sleep 1; \
		$(SILENT_MAKE) -f $(THIS_FILE) push_auth; \
	fi;
	@CHECK_SIG=`java -jar $(APPLET_PATH)/gp.jar -l 2>/dev/null | grep 45757477747536417072 | grep Applet`; \
	if [ "$$CHECK_SIG" != "" ]; then \
		echo -n "\r\033[1;41m Error: you have inserted a smartcard already programmed with a SIG applet, but you have asked to use one smartcard per token."; \
		echo -n "Please insert a virgin token, or purge the current one!\033[1;m"; \
		sleep 1; \
		$(SILENT_MAKE) -f $(THIS_FILE) push_auth; \
	fi;
endif
	@java -jar $(APPLET_PATH)/gp.jar --force --install $(APPLET_PATH)/build_auth/wookey_auth.cap;

push_dfu:
	@CHECK_CARD=`java -jar $(APPLET_PATH)/gp.jar -i 2>/dev/null | grep ATR`; \
	while [ "$$CHECK_CARD" = "" ]; do \
		echo -n "\r\033[1;41m No token detected. Please insert your DFU token (waiting) ...\033[1;m"; \
		CHECK_CARD=`java -jar $(APPLET_PATH)/gp.jar -i 2>/dev/null | grep ATR`; \
		sleep 1; \
	done;
ifeq ("$(USE_DIFFERENT_PHYSICAL_TOKENS)","y")
	@# Check that we do not have another token here ...
	@CHECK_AUTH=`java -jar $(APPLET_PATH)/gp.jar -l 2>/dev/null | grep 45757477747536417070 | grep Applet`; \
	if [ "$$CHECK_AUTH" != "" ]; then \
		echo -n "\r\033[1;41m Error: you have inserted a smartcard already programmed with a AUTH applet, but you have asked to use one smartcard per token."; \
		echo -n "Please insert a virgin token, or purge the current one!\033[1;m"; \
		sleep 1; \
		$(SILENT_MAKE) -f $(THIS_FILE) push_dfu; \
	fi;
	@CHECK_SIG=`java -jar $(APPLET_PATH)/gp.jar -l 2>/dev/null | grep 45757477747536417072 | grep Applet`; \
	if [ "$$CHECK_SIG" != "" ]; then \
		echo -n "\r\033[1;41m Error: you have inserted a smartcard already programmed with a SIG applet, but you have asked to use one smartcard per token."; \
		echo -n "Please insert a virgin token, or purge the current one!\033[1;m"; \
		sleep 1; \
		$(SILENT_MAKE) -f $(THIS_FILE) push_dfu; \
	fi;
endif
	@java -jar $(APPLET_PATH)/gp.jar --force --install $(APPLET_PATH)/build_dfu/wookey_dfu.cap;

push_sig:
ifeq ("$(USE_SIG_TOKEN)","USE_SIG_TOKEN")
	@CHECK_CARD=`java -jar $(APPLET_PATH)/gp.jar -i 2>/dev/null | grep ATR`; \
	while [ "$$CHECK_CARD" = "" ]; do \
		echo -n "\r\033[1;41m No token detected. Please insert your SIG token (waiting) ...\033[1;m"; \
		CHECK_CARD=`java -jar $(APPLET_PATH)/gp.jar -i 2>/dev/null | grep ATR`; \
		sleep 1; \
	done;
ifeq ("$(USE_DIFFERENT_PHYSICAL_TOKENS)","y")
	@# Check that we do not have another token here ...
	@CHECK_AUTH=`java -jar $(APPLET_PATH)/gp.jar -l 2>/dev/null | grep 45757477747536417070 | grep Applet`; \
	if [ "$$CHECK_AUTH" != "" ]; then \
		echo -n "\r\033[1;41m Error: you have inserted a smartcard already programmed with a AUTH applet, but you have asked to use one smartcard per token."; \
		echo -n "Please insert a virgin token, or purge the current one!\033[1;m"; \
		sleep 1; \
		$(SILENT_MAKE) -f $(THIS_FILE) push_sig; \
	fi;
	@CHECK_DFU=`java -jar $(APPLET_PATH)/gp.jar -l 2>/dev/null | grep 45757477747536417071 | grep Applet`; \
	if [ "$$CHECK_DFU" != "" ]; then \
		echo -n "\r\033[1;41m Error: you have inserted a smartcard already programmed with a DFU applet, but you have asked to use one smartcard per token."; \
		echo -n "Please insert a virgin token, or purge the current one!\033[1;m"; \
		sleep 1; \
		$(SILENT_MAKE) -f $(THIS_FILE) push_sig; \
	fi;
endif
	@java -jar $(APPLET_PATH)/gp.jar --force --install $(APPLET_PATH)/build_sig/wookey_sig.cap;
else
	@echo "Sorry, the signature applet does not exist since the user asked to use local firmware signature/encryption ...";
endif


.PHONY: applets
