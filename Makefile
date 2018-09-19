PROJ_FILES = ../
-include $(PROJ_FILES)/Makefile.conf
-include $(PROJ_FILES)/Makefile.gen

CC=gcc
LD=ld
AR=ar
RANLIB=ranlib

all: applet pcsc_test

pcsc_test:
	cd pcsc_host_tests && make token && make crypto

clean_pcsc_test:
	cd pcsc_host_tests && make clean

applet:
	$(call if_changed,mkapplet)

clean_applet:
	cd applet && ant clean

clean: clean_applet clean_pcsc_test

push:
	java -jar applet/gp.jar --reinstall $(BUILD_DIR)/javacard/applet/goodusb.cap

.PHONY: applet
