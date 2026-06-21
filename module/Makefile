# Out-of-tree build of the krunc Rust kernel module.
#
#   make            # build krunc.ko against $KDIR
#   make clean
#
# KDIR must point at a kernel source tree that was built with CONFIG_RUST=y and
# the krunc vmlinux export shim (see scripts/build-kernel.sh).
KDIR ?= $(HOME)/linux-6.18
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) LLVM=1 modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) LLVM=1 clean

.PHONY: all clean
