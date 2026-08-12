# PTE追踪驱动 Makefile — GKI 内核树独立模块编译版
# 用法（在 Actions 里，内核 gki_defconfig 构建后）:
#   make LLVM=1 ARCH=arm64 ... -C <common源码树> M=<本目录> modules
obj-m := pte_driver.o
pte_driver-objs := pte_driver.o

KERNEL_DIR ?= $(PWD)/common

.PHONY: all clean modules_prepare

all: modules

modules:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

modules_prepare:
	$(MAKE) -C $(KERNEL_DIR) modules_prepare

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
