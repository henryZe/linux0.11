# DeScrambler Core driver
# Copyright(C) 2014 ALi Corporation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

KERNELDIR := ../../../..

obj-$(CONFIG_ALI_DSC) += alidsc.o

alidsc-y := ca_dsc_core.o \
	ca_dsc_ioctl.o ca_dsc_rpc.o \
	ca_dsc_session_engine.o ca_dsc_sbm.o

alidsc-$(CONFIG_DSC_LEGACY_IOCTL) += ca_dsc_ioctl_legacy.o
alidsc-$(CONFIG_DEBUG_FS) += ca_dsc_dbgfs.o
alidsc-$(CONFIG_SYSFS) += ca_dsc_sysfs.o

sources = $(wildcard *.c *.h Makefile)

CHECKPATCH=$(KERNELDIR)/scripts/checkpatch.pl
checkpatch:
	$(foreach var, $(sources), $(CHECKPATCH) -f $(var);)

clean:
	rm -f *.mod.c
	rm -f *.ko .*.ko.cmd
	rm -f *.o .*.o.cmd
	rm -f modules.*
	rm -fr .tmp_versions

