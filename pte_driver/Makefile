# PTE追踪驱动 Makefile
# 关键：设备 CONFIG_CFI_CLANG=y 严格模式(OnePlus 4k 内核)。
#   ⚠️ 不要禁用 CFI/KCFI！paradise(6.6.ko, 能加载) 保留 __kcfi_typeid_ 符号,
#      全局 -fno-sanitize=kcfi 会导致模块 ioctl 回调无 typeid, 设备内核
#      经函数指针间接调用时 KCFI 校验失败 → "CFI: Fatal" panic 重启。
#   ✅ 完全复刻 paradise: 不加任何 -fno-sanitize, 由内核 config(CFI_CLANG=y)自动生成 typeid。
obj-m := pte_driver.o