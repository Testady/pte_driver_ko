# PTE追踪驱动 Makefile — 泪心终极配方（禁用 CFI/KCFI/SCS/LTO）
# 关键：设备 CONFIG_CFI_CLANG=y 严格模式时，模块必须 "禁用CFI" 编译才能加载，
#       而非开启kcfi。泪心已实测：-fno-sanitize=kcfi 是防止 panic 重启的根因级修复。
# 用法（Actions 里，内核 O=out 分离构建后）:
#   make -C <common源码树> O=out ... LLVM=1 M=本目录 modules
obj-m := pte_driver.o
KERNEL_DIR ?= $(PWD)/common
OUT := out

ccflags-y += -fno-sanitize=cfi
ccflags-y += -fno-sanitize=cfi-icall
ccflags-y += -fno-sanitize=kcfi
ccflags-y += -fno-stack-protector
ccflags-y += -fno-sanitize=shadow-call-stack
ccflags-y += -fno-lto

CFLAGS_pte_driver.o := -fno-sanitize=cfi -fno-sanitize=cfi-icall -fno-sanitize=kcfi -fno-stack-protector -fno-sanitize=shadow-call-stack -fno-lto

KBUILD_MODPOST_WARN := 1

.PHONY: all clean modules_prepare
all: modules
modules:
	$(MAKE) -C $(KERNEL_DIR) LLVM=1 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=clang LD=ld.lld KCFLAGS+=-Wno-error O=$(OUT) KBUILD_MODPOST_WARN=1 M=$(PWD) modules
modules_prepare:
	$(MAKE) -C $(KERNEL_DIR) LLVM=1 ARCH=arm64 O=$(OUT) modules_prepare
clean:
	$(MAKE) -C $(KERNEL_DIR) LLVM=1 ARCH=arm64 O=$(OUT) M=$(PWD) clean