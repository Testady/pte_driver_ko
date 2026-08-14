/*
 * PTE追踪内核驱动 — ARM64 Linux 内核模块
 * 
 * 功能：通过修改页表项(PTE)触发缺页异常，实现跨线程的代码执行追踪。
 * 支持：5.10 / 5.15 / 6.1 / 6.6 / 6.12 内核版本
 * 
 * ioctl命令：
 *   0x400010 CMD_CHECK_DRIVER   — 驱动检查
 *   0x400011 CMD_READ           — 跨进程内存读取
 *   0x400012 CMD_WRITE          — 跨进程内存写入
 *   0x400013 CMD_MODULE_BASE    — 获取模块基地址
 *   0x400030 CMD_PTE_INSTALL_TRACK   — 安装PTE追踪
 *   0x400031 CMD_PTE_UNINSTALL_TRACK — 卸载PTE追踪
 *   0x400032 CMD_PTE_GET_HIT         — 获取命中信息
 *   0x400033 CMD_PTE_RESUME          — 恢复追踪
 *   0x400034 CMD_PTE_SET_REG_MODIFY  — 设置寄存器修改
 *   0x400035 CMD_PTE_CLEAR_REG_MODIFY— 清除寄存器修改
 *   0x400036 CMD_PTE_SUSPEND         — 暂停追踪
 *   0x400037 CMD_PTE_QUERY_PAGE      — 查询页信息
 *   0x6664   OP_GET_IDZT_PIKACHU    — 获取模块基地址（兼容）
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/ioctl.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/kprobes.h>
#include <linux/hugetlb.h>
#include <linux/version.h>
#include <generated/utsrelease.h>
#include <linux/delay.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/processor.h>
#include <asm/fpsimd.h>
#include <asm/insn.h>

#include <linux/random.h>

#ifndef __nocfi
#define __nocfi __attribute__((no_sanitize("cfi")))
#endif

#define DRIVER_NAME     "niuto"
/* 节点名在运行时随机化（modname 伪随机，避免固定 /dev/niuto01 特征） */
#define DEVICE_NAME     DEV_NAME_RANDOM
#define DEV_NAME_PREFIX "nv"   /* nondescript prefix（伪装成常见驱动缩写） */
#define DEV_NAME_LEN    8
#define TAG             "[nv]"
/* 无痕日志：静默所有内核日志，避免 dmesg 残留特征。
 * 需在所有 pr_* 宏使用之前生效，故放在 include 之后、首个使用点之前。 */
#undef pr_info
#undef pr_warn
#undef pr_err
#undef pr_debug
#undef pr_notice
#undef printk
#define pr_info(fmt, ...)    do { } while (0)
#define pr_warn(fmt, ...)    do { } while (0)
#define pr_err(fmt, ...)     do { } while (0)
#define pr_debug(fmt, ...)   do { } while (0)
#define pr_notice(fmt, ...)  do { } while (0)
#define printk(fmt, ...)     do { } while (0)
/* 运行时随机节点名 buffer */
static char dev_node_name[DEV_NAME_LEN + 1];
static bool dev_name_ready = false;

/*
 * 生成随机节点名：混合小写字母+数字（非纯hex，规避"8位hex"特征扫描），
 * 每次 insmod 不同，伪装成普通系统设备命名。
 */
static void rand_dev_name(void)
{
    /* base32 风格字符集（去掉 0/O/1/I/l 等易混淆字符），半随机更自然 */
    static const char set[] = "abcdefghjkmnpqrstuvwxyz23456789";
    u8 rnd[8];
    int i;

    dev_node_name[0] = '\0';
    get_random_bytes(rnd, sizeof(rnd));
    for (i = 0; i < DEV_NAME_LEN; i++) {
        dev_node_name[i] = set[rnd[i] % (sizeof(set) - 1)];
    }
    dev_node_name[DEV_NAME_LEN] = '\0';
    dev_name_ready = true;
}

#define DEV_NAME_RANDOM dev_node_name

/* ==================== ioctl 命令定义 ==================== */
#define CMD_CHECK_DRIVER        0x400010
#define CMD_READ                0x400011
#define CMD_WRITE               0x400012
#define CMD_MODULE_BASE         0x400013
#define CMD_PTE_INSTALL_TRACK   0x400030
#define CMD_PTE_UNINSTALL_TRACK 0x400031
#define CMD_PTE_GET_HIT         0x400032
#define CMD_PTE_RESUME          0x400033
#define CMD_PTE_SET_REG_MODIFY  0x400034
#define CMD_PTE_CLEAR_REG_MODIFY 0x400035
#define CMD_PTE_SUSPEND         0x400036
#define CMD_PTE_QUERY_PAGE      0x400037
#define OP_GET_IDZT_PIKACHU     0x6664

#define MAX_TRACK_ENTRIES       64
#define MAX_REG_MODIFY          10

/* ==================== 与用户层共享的数据结构 ====================
 * 对齐说明：COPY_MEMORY/MODULE_BASE/DRIVER_CHECK/PERF_REQUEST 采用标准
 * (非PACKED) aarch64 对齐，与用户态 辅助类.h 对应结构一致；
 * PTE 相关结构(应用端在 #pragma pack(push,1) 区块)才使用 PACKED。 */
struct copy_memory {
    pid_t pid;
    uintptr_t addr;
    void *buffer;
    size_t size;
};

struct module_base_req {
    pid_t pid;
    char *name;
    uintptr_t base;
};

struct driver_check {
    char name[64];
    bool is_loaded;
};

struct perf_request {
    pid_t pid;
    uint64_t proc_virt_addr;
    uint16_t hwbp_len;
    uint16_t hwbp_type;
    size_t buf_size;
    uint64_t src_buf;
};

#pragma pack(push, 1)
struct reg_modify_config {
    int reg_index;
    uint8_t reg_type;
    union {
        uint32_t int32_val;
        uint64_t int64_val;
        float float_val;
        double double_val;
    } value;
};

struct my_user_pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
    uint64_t orig_x0;
    uint64_t syscallno;
};

struct my_user_fpsimd_state {
    __uint128_t vregs[32];
    uint32_t fpsr;
    uint32_t fpcr;
    uint32_t __reserved[2];
};

struct pte_track_request {
    pid_t pid;
    uint64_t virt_addr;
    uint64_t handle;
    uint64_t page_pa;
    uint32_t page_size;
    uint32_t flags;
};

struct pte_hit_info {
    uint64_t handle;
    uint64_t hit_addr;
    uint64_t hit_time;
    struct my_user_pt_regs regs_info;
    struct my_user_fpsimd_state fpsimd_info;
    uint64_t fault_addr;
    uint32_t fault_flags;
    uint32_t hit_count;
};

struct pte_reg_modify_batch {
    uint64_t handle;
    uint32_t config_count;
    uint32_t reserved;
    /* struct reg_modify_config configs[]; 变长数组 */
};

#pragma pack(pop)

/* ==================== 驱动侧追踪条目 ==================== */
struct pte_track_entry {
    uint64_t handle;
    pid_t pid;
    struct task_struct *task;
    struct mm_struct *mm;
    uint64_t virt_addr;           /* 页对齐 */
    uint64_t page_pa;
    uint32_t page_size;
    uint32_t flags;
    pte_t orig_pte;               /* 原始PTE */
    pte_t *ptep;                  /* PTE指针 */
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    spinlock_t lock;
    bool installed;
    bool suspended;
    struct pte_hit_info hit;      /* 最新命中信息 */
    wait_queue_head_t hit_wq;     /* 命中等待队列 */
    bool hit_ready;               /* 命中就绪标志 */
    /* 寄存器修改配置 */
    struct reg_modify_config reg_configs[MAX_REG_MODIFY];
    int reg_config_count;
    /* 链表 */
    struct list_head list;
};

/* ==================== 全局数据 ==================== */
static struct list_head track_list;
static DEFINE_SPINLOCK(track_list_lock);
static uint64_t next_handle = 0x1000;
static struct miscdevice *misc_dev_ptr = NULL;

/* ==================== kprobe 缺页拦截 ==================== */
static struct kprobe kp_do_page_fault;
static bool kprobe_registered = false;

/* 需要动态查找的函数指针 */
static void *(*kallsyms_lookup_name_ptr)(const char *name) = NULL;
static void (*fpsimd_save_state_ptr)(struct user_fpsimd_state *state) = NULL;

/* ==================== 前向声明 ==================== */
static int pte_find_and_modify(struct pte_track_entry *entry);
static int pte_modify_for_track(struct pte_track_entry *entry);
static int pte_restore_original(struct pte_track_entry *entry);
static int pte_apply_reg_modify(struct pte_track_entry *entry, struct pt_regs *regs);
static void pte_save_regs_snapshot(struct pte_track_entry *entry, struct pt_regs *regs);
static struct pte_track_entry *pte_find_by_handle(uint64_t handle);
static struct pte_track_entry *pte_find_by_addr(struct mm_struct *mm, uint64_t fault_addr);

/* ==================== 内存读写实现 ==================== */
/* 说明：不去动 PTE 追踪的锁/页表（自踩陷阱保护方案会在读路径持 entry->lock
 *       调 pte_restore_original + down_read(mmap_lock)，与 kprobe 缺页拦截
 *       形成锁顺序反转死锁，触发 QCOM watchdog 复位）。此处仅做纯读路径的
 *       安全增强：kmap_local_page（5.11+ 弃用 kmap_atomic）+ 空指针校验。 */
static int driver_read_process_mem(pid_t pid, uintptr_t addr, void *buf, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct page *page = NULL;
    void *map_addr = NULL;
    unsigned long offset;
    int ret = -1;
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        pr_err(TAG "read: pid %d not found\n", pid);
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) return -ESRCH;
    offset = addr & ~PAGE_MASK;
    /* 使用 get_user_pages_remote */
    down_read(&mm->mmap_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
    ret = pin_user_pages_remote(mm, addr & PAGE_MASK, 1,
                                FOLL_FORCE, &page, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    ret = pin_user_pages_remote(mm, addr & PAGE_MASK, 1,
                                FOLL_FORCE, &page, NULL, NULL);
#else
    ret = get_user_pages_remote(mm, addr & PAGE_MASK, 1,
                                FOLL_FORCE, &page, NULL, NULL);
#endif
    up_read(&mm->mmap_lock);
    if (ret <= 0 || !page) {
        pr_err(TAG "read: get_user_pages failed (ret=%d)\n", ret);
        mmput(mm);
        return -EFAULT;
    }
    map_addr = kmap_local_page(page);
    if (!map_addr) {
        unpin_user_page(page);
        mmput(mm);
        return -EIO;
    }
    if (size > PAGE_SIZE - offset) size = PAGE_SIZE - offset;
    memcpy(buf, map_addr + offset, size);
    kunmap_local(map_addr);
    unpin_user_page(page);
    mmput(mm);
    return 0;
}

static int driver_write_process_mem(pid_t pid, uintptr_t addr, void *buf, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct page *page = NULL;
    void *map_addr = NULL;
    unsigned long offset;
    int ret = -1;
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        pr_err(TAG "write: pid %d not found\n", pid);
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) return -ESRCH;
    offset = addr & ~PAGE_MASK;
    down_read(&mm->mmap_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
    ret = pin_user_pages_remote(mm, addr & PAGE_MASK, 1,
                                FOLL_FORCE | FOLL_WRITE, &page, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    ret = pin_user_pages_remote(mm, addr & PAGE_MASK, 1,
                                FOLL_FORCE | FOLL_WRITE, &page, NULL, NULL);
#else
    ret = get_user_pages_remote(mm, addr & PAGE_MASK, 1,
                                FOLL_FORCE | FOLL_WRITE, &page, NULL, NULL);
#endif
    up_read(&mm->mmap_lock);
    if (ret <= 0 || !page) {
        pr_err(TAG "write: get_user_pages failed (ret=%d)\n", ret);
        mmput(mm);
        return -EFAULT;
    }
    map_addr = kmap_local_page(page);
    if (!map_addr) {
        unpin_user_page(page);
        mmput(mm);
        return -EIO;
    }
    if (size > PAGE_SIZE - offset) size = PAGE_SIZE - offset;
    memcpy(map_addr + offset, buf, size);
    kunmap_local(map_addr);
    set_page_dirty_lock(page);
    unpin_user_page(page);
    mmput(mm);
    return 0;
}

/* ==================== PTE 遍历与修改 ==================== */

/*
 * 在目标进程的页表中查找虚拟地址对应的PTE。
 * 返回PTE指针（已锁定）并填充entry中的相关字段。
 */
static int pte_lookup_in_mm(struct mm_struct *mm, uint64_t virt_addr,
                            pte_t **ptep_out, pgd_t **pgd_out,
                            p4d_t **p4d_out, pud_t **pud_out, pmd_t **pmd_out)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;
    spinlock_t *ptl;

    pgd = pgd_offset(mm, virt_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return -EINVAL;

    p4d = p4d_offset(pgd, virt_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return -EINVAL;

    pud = pud_offset(p4d, virt_addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return -EINVAL;

    pmd = pmd_offset(pud, virt_addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return -EINVAL;

    /* 处理大页 */
#ifdef CONFIG_HUGETLB_PAGE
    if (pmd_huge(*pmd)) {
        pr_warn(TAG "Huge page at 0x%llx, not supported\n", virt_addr);
        return -EOPNOTSUPP;
    }
#endif

    ptep = pte_offset_map_lock(mm, pmd, virt_addr, &ptl);
    if (!ptep)
        return -ENOMEM;

    if (!pte_present(*ptep)) {
        pte_unmap_unlock(ptep, ptl);
        return -EFAULT;
    }

    *ptep_out = ptep;
    if (pgd_out) *pgd_out = pgd;
    if (p4d_out) *p4d_out = p4d;
    if (pud_out) *pud_out = pud;
    if (pmd_out) *pmd_out = pmd;

    return 0;
}

/*
 * 修改PTE：清除PTE_VALID位（bit0），使访问触发fault。
 * ARM64 PTE格式：
 *   bit 0   = PTE_VALID (有效位)
 *   bit 10  = PTE_AF (Access Flag)
 *   bit 53  = PTE_XN (XN for block/table descriptor)
 *   bit 54  = PTE_XN (XN for block/table descriptor)
 *
 * 我们清除PTE_VALID使页表项完全无效，
 * 后续访问将触发translation fault。
 */
static int pte_modify_for_track(struct pte_track_entry *entry)
{
    struct mm_struct *mm = entry->mm;
    uint64_t virt_addr = entry->virt_addr;
    pte_t *ptep;
    pte_t pte;
    int ret;

    ret = pte_lookup_in_mm(mm, virt_addr, &ptep,
                           &entry->pgd, &entry->p4d,
                           &entry->pud, &entry->pmd);
    if (ret < 0)
        return ret;

    entry->ptep = ptep;

    /* 保存原始PTE */
    pte = *ptep;
    entry->orig_pte = pte;

    /* 提取物理页地址 */
    entry->page_pa = pte_pfn(pte) << PAGE_SHIFT;
    entry->page_size = PAGE_SIZE;

    pr_debug(TAG "PTE at 0x%llx: orig=0x%016llx, pa=0x%llx, size=%u\n",
            virt_addr, pte_val(pte), entry->page_pa, entry->page_size);

    /* 使PTE无效 — 清除PTE_VALID (bit0) */
    pte = clear_pte_bit(pte, __pgprot(PTE_VALID));
    /* 直接写 PTE 指针，绕过 set_pte_at 宏：
     * set_pte_at 在 ARM64 GKI（CONFIG_ARM64_MTE + mmu_notifier）会内联调用
     * 未导出符号 mte_sync_tags / __mmu_notifier_arch_invalidate_secondary_tlbs，
     * 外部模块编译时会 modpost undefined。
     */
    *ptep = pte;
    /* TLB刷新（flush_tlb_page 在 ARM64 GKI+MMU_NOTIFIER 会调用未导出符号
     * __mmu_notifier_arch_invalidate_secondary_tlbs，外部模块无法编译，故此处跳过。
     * PTE 修改本身属高危操作，后续应改用导出 API 或由内核侧完成。）
     */
    /* flush_tlb_page(find_vma(mm, virt_addr), virt_addr); */

    /* 注意：ptep现在由entry持有，在卸载时解锁 */
    entry->installed = true;
    return 0;
}

/*
 * 恢复原始PTE
 */
static int pte_restore_original(struct pte_track_entry *entry)
{
    if (!entry->installed || !entry->ptep)
        return -EINVAL;

    /* 恢复原始PTE */
    *entry->ptep = entry->orig_pte;
    /* TLB刷新跳过（同 pte_modify_for_track 原因，外部模块无法引用未导出 mmu_notifier 符号） */
    /* flush_tlb_page(find_vma(mm, entry->virt_addr), entry->virt_addr); */

    entry->installed = false;
    pr_debug(TAG "PTE restored for handle 0x%llx\n", entry->handle);
    return 0;
}

/* ==================== PTE追踪条目管理 ==================== */

static struct pte_track_entry *pte_find_by_handle(uint64_t handle)
{
    struct pte_track_entry *entry;
    list_for_each_entry(entry, &track_list, list) {
        if (entry->handle == handle)
            return entry;
    }
    return NULL;
}

static struct pte_track_entry *pte_find_by_addr(struct mm_struct *mm, uint64_t fault_addr)
{
    struct pte_track_entry *entry;
    uint64_t fault_page = fault_addr & PAGE_MASK;

    list_for_each_entry(entry, &track_list, list) {
        if (entry->mm == mm && entry->installed && !entry->suspended) {
            if (entry->virt_addr == fault_page)
                return entry;
        }
    }
    return NULL;
}

static struct pte_track_entry *pte_create_entry(pid_t pid, uint64_t virt_addr,
                                                 uint32_t flags)
{
    struct pte_track_entry *entry;
    struct task_struct *task;
    struct mm_struct *mm;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return ERR_PTR(-ESRCH);
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return ERR_PTR(-ESRCH);
    }

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        mmput(mm);
        put_task_struct(task);
        return ERR_PTR(-ENOMEM);
    }

    INIT_LIST_HEAD(&entry->list);
    spin_lock_init(&entry->lock);
    init_waitqueue_head(&entry->hit_wq);

    /* 分配句柄ID */
    spin_lock(&track_list_lock);
    entry->handle = next_handle++;
    spin_unlock(&track_list_lock);

    entry->pid = pid;
    entry->task = task;
    entry->mm = mm;
    entry->virt_addr = virt_addr & PAGE_MASK;
    entry->flags = flags;
    entry->installed = false;
    entry->suspended = false;
    entry->hit_ready = false;
    entry->reg_config_count = 0;
    memset(&entry->hit, 0, sizeof(entry->hit));

    return entry;
}

static void pte_destroy_entry(struct pte_track_entry *entry)
{
    if (!entry)
        return;

    /* 恢复PTE */
    if (entry->installed && entry->ptep) {
        *entry->ptep = entry->orig_pte;
        spinlock_t *ptl = pte_lockptr(entry->mm, entry->pmd);
        pte_unmap_unlock(entry->ptep, ptl);
    }

    if (entry->mm)
        mmput(entry->mm);
    if (entry->task)
        put_task_struct(entry->task);

    kfree(entry);
}

/* ==================== 寄存器操作 ==================== */

/*
 * 从当前上下文保存通用寄存器和浮点寄存器快照
 */
static void pte_save_regs_snapshot(struct pte_track_entry *entry, struct pt_regs *regs)
{
    int i;
    uint64_t *fpsimd_ptr;
    struct user_fpsimd_state *fpsimd;

    /* 通用寄存器 */
    for (i = 0; i < 31; i++)
        entry->hit.regs_info.regs[i] = regs->regs[i];
    entry->hit.regs_info.sp = regs->sp;
    entry->hit.regs_info.pc = regs->pc;
    entry->hit.regs_info.pstate = regs->pstate;
    entry->hit.regs_info.orig_x0 = regs->orig_x0;
    entry->hit.regs_info.syscallno = regs->syscallno;

    entry->hit.hit_addr = regs->pc;
    entry->hit.hit_time = ktime_get_real_ns();
    entry->hit.hit_count++;

    /* 浮点寄存器 — 先从硬件同步到内存 */
    /* [patched] fpsimd_save_state 是裸函数指针，在 handler/原子上下文调用高危，
     * 且当前缺页kprobe已默认禁用。直接用当前线程的 fpsimd_state 内存读取即可。 */
    fpsimd = &current->thread.uw.fpsimd_state;

    /* 读取V0-V31 (128-bit) */
    fpsimd_ptr = (uint64_t *)fpsimd->vregs;
    for (i = 0; i < 32; i++) {
        entry->hit.fpsimd_info.vregs[i] = *((__uint128_t *)(fpsimd_ptr + i * 2));
    }
    entry->hit.fpsimd_info.fpsr = fpsimd->fpsr;
    entry->hit.fpsimd_info.fpcr = fpsimd->fpcr;
}

/*
 * 应用寄存器修改：修改通用寄存器或浮点寄存器
 */
static int pte_apply_reg_modify(struct pte_track_entry *entry, struct pt_regs *regs)
{
    int i;
    struct user_fpsimd_state *fpsimd;

    if (entry->reg_config_count <= 0)
        return 0;

    fpsimd = &current->thread.uw.fpsimd_state;

    for (i = 0; i < entry->reg_config_count; i++) {
        struct reg_modify_config *cfg = &entry->reg_configs[i];
        int idx = cfg->reg_index;

        if (idx >= 0 && idx < 31) {
            /* 通用寄存器 X0-X30 */
            switch (cfg->reg_type) {
            case 0: /* INT32 */
                regs->regs[idx] = (regs->regs[idx] & 0xFFFFFFFF00000000ULL) |
                                  (cfg->value.int32_val & 0xFFFFFFFFULL);
                break;
            case 1: /* INT64 */
                regs->regs[idx] = cfg->value.int64_val;
                break;
            case 2: /* FLOAT */
                *(float *)&regs->regs[idx] = cfg->value.float_val;
                break;
            case 3: /* DOUBLE */
                *(double *)&regs->regs[idx] = cfg->value.double_val;
                break;
            default:
                break;
            }
        } else if (idx == 31) {
            /* SP */
            regs->sp = cfg->value.int64_val;
        } else if (idx >= 100 && idx <= 131) {
            /* 浮点寄存器 V0-V31 (reg_index 100-131) */
            int v_idx = idx - 100;
            float *vreg_ptr = (float *)&fpsimd->vregs[v_idx];
            switch (cfg->reg_type) {
            case 0: /* INT32 */
                *(int32_t *)vreg_ptr = cfg->value.int32_val;
                break;
            case 1: /* INT64 */
                *(int64_t *)vreg_ptr = cfg->value.int64_val;
                break;
            case 2: /* FLOAT */
                vreg_ptr[0] = cfg->value.float_val;
                break;
            case 3: /* DOUBLE */
                *(double *)vreg_ptr = cfg->value.double_val;
                break;
            default:
                break;
            }
        }
    }

    /* 标记浮点状态已修改，返回用户空间时重新加载 */
    current->thread.fpsimd_cpu = NR_CPUS;
    set_thread_flag(TIF_FOREIGN_FPSTATE);

    return 0;
}

/* ==================== kprobe 缺页拦截 ==================== */

/*
 * do_page_fault pre_handler
 * 在缺页处理之前检查是否是我们追踪的地址
 */
/* pre_handler: 让其自然携带与 kprobe_pre_handler_t 匹配的 KCFI typeid */
static int pte_page_fault_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long fault_addr;
    unsigned long esr;
    struct pt_regs *user_regs;
    struct pte_track_entry *entry;
    struct mm_struct *mm;

    if (!current || !current->mm)
        return 0; /* 内核线程，忽略 */

    mm = current->mm;

    /*
     * ARM64 do_page_fault 参数:
     *   x0 = far (fault address register)
     *   x1 = esr (exception syndrome register)
     *   x2 = regs (struct pt_regs *)
     */
    fault_addr = regs->regs[0];
    esr = regs->regs[1];
    user_regs = (struct pt_regs *)regs->regs[2];

    /* 快速过滤：检查fault地址是否在任何追踪页中 */
    spin_lock(&track_list_lock);
    entry = pte_find_by_addr(mm, fault_addr);
    spin_unlock(&track_list_lock);

    if (!entry)
        return 0; /* 不匹配，正常处理缺页 */

    /* 匹配！处理PTE追踪命中 */
    pr_debug(TAG "PTE hit: handle=0x%llx, fault=0x%lx, pc=0x%llx\n",
             entry->handle, fault_addr, user_regs->pc);

    /* 保存命中信息 */
    spin_lock(&entry->lock);

    entry->hit.fault_addr = fault_addr;
    entry->hit.fault_flags = (uint32_t)(esr & 0xFFFFFFFF);
    entry->hit.handle = entry->handle;

    /* 保存寄存器快照 */
    if (user_regs)
        pte_save_regs_snapshot(entry, user_regs);

    /* 应用寄存器修改 */
    if (user_regs && entry->reg_config_count > 0)
        pte_apply_reg_modify(entry, user_regs);

    /* 恢复原始PTE（使后续访问正常） */
    /* 注意：在kprobe handler中不能直接修改目标进程的页表。
     * 我们标记需要恢复，实际操作延迟到用户层调用CMD_PTE_RESUME或
     * 在post_handler中处理。这里我们保留PTE无效状态，
     * 但设置一个标志让do_page_fault跳过此地址。
     *
     * 实际上，最简单的方法是在这里恢复PTE：
     * set_pte_at(entry->mm, entry->virt_addr, entry->ptep, entry->orig_pte);
     * flush_tlb_page(vma, entry->virt_addr);
     * 但需要获取vma（可能需要mmap_lock，在kprobe上下文中危险）。
     *
     * 替代方案：让缺页处理正常返回（不恢复PTE），
     * 在用户层获取命中信息后再调用CMD_PTE_RESUME来恢复。
     * 此处我们使用kprobe来标记命中，然后让do_page_fault
     * 自然失败（因为PTE无效），进程收到SIGSEGV。
     *
     * 更好的方案：恢复PTE并返回，让do_page_fault重试。
     */

    entry->hit_ready = true;
    spin_unlock(&entry->lock);

    /* [patched] 危险块已移除：
     * 原代码在 kprobe/原子上下文中调用了 wake_up_interruptible()（触发调度）、
     * find_vma()（需要 mmap_lock 可能睡眠）、set_pte_at()+flush_tlb_page()
     * （缺页路径改页表易死锁/递归缺页）。这些在开启 KASAN 的 6.6 内核上必然 panic。
     *
     * 现在 handler 只做：spinlock 查找 + 命中标记 + 寄存器快照/修改（纯内存操作，安全），
     * PTE 恢复统一交给用户层 ioctl CMD_PTE_RESUME（在可睡眠的 ioctl 上下文执行，
     * 调用 pte_restore_original）。这里不 wake_up、不 find_vma、不改页表。
     */
    return 0; /* 已标记命中，不在此恢复PTE；恢复交给 CMD_PTE_RESUME */
}

/* ==================== ioctl 处理 ==================== */

static long driver_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0;

    switch (cmd) {

    case CMD_CHECK_DRIVER: {
        struct driver_check dc;
        if (copy_from_user(&dc, (void __user *)arg, sizeof(dc)))
            return -EFAULT;
        dc.is_loaded = true;
        if (copy_to_user((void __user *)arg, &dc, sizeof(dc)))
            return -EFAULT;
        ret = 1;
        break;
    }

    case CMD_READ: {
        struct copy_memory cm;
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;
        if (!cm.buffer || cm.size == 0)
            return -EINVAL;
        ret = driver_read_process_mem(cm.pid, cm.addr, cm.buffer, cm.size);
        if (ret == 0) ret = 1;
        break;
    }

    case CMD_WRITE: {
        struct copy_memory cm;
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;
        if (!cm.buffer || cm.size == 0)
            return -EINVAL;
        ret = driver_write_process_mem(cm.pid, cm.addr, cm.buffer, cm.size);
        if (ret == 0) ret = 1;
        break;
    }

    case CMD_MODULE_BASE: {
        struct module_base_req mb;
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)))
            return -EFAULT;
        /* 返回模块自身加载基地址（用于兼容） */
        mb.base = (uintptr_t)THIS_MODULE->mem[MOD_TEXT].base;
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
            return -EFAULT;
        ret = 1;
        break;
    }

    case OP_GET_IDZT_PIKACHU: {
        struct module_base_req mb;
        mb.base = 10086; /* 魔数验证 */
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
            return -EFAULT;
        ret = 1;
        break;
    }

    /* ============ PTE 追踪命令 ============ */

    case CMD_PTE_INSTALL_TRACK: {
        struct pte_track_request req;
        struct pte_track_entry *entry;
        unsigned long irq_flags;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        if (req.pid <= 0)
            return -EINVAL;

        /* 创建追踪条目 */
        entry = pte_create_entry(req.pid, req.virt_addr, req.flags);
        if (IS_ERR(entry))
            return PTR_ERR(entry);

        /* 修改PTE触发fault */
        ret = pte_modify_for_track(entry);
        if (ret < 0) {
            pr_err(TAG "Failed to modify PTE for 0x%llx: %d\n",
                   req.virt_addr, ret);
            pte_destroy_entry(entry);
            return ret;
        }

        /* 添加到全局链表 */
        spin_lock_irqsave(&track_list_lock, irq_flags);
        list_add(&entry->list, &track_list);
        spin_unlock_irqrestore(&track_list_lock, irq_flags);

        /* 返回结果 */
        req.handle = entry->handle;
        req.page_pa = entry->page_pa;
        req.page_size = entry->page_size;

        if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
            spin_lock_irqsave(&track_list_lock, irq_flags);
            list_del(&entry->list);
            spin_unlock_irqrestore(&track_list_lock, irq_flags);
            pte_destroy_entry(entry);
            return -EFAULT;
        }

        pr_debug(TAG "Installed PTE track: handle=0x%llx, pid=%d, va=0x%llx\n",
                entry->handle, req.pid, req.virt_addr);
        ret = 1;
        break;
    }

    case CMD_PTE_UNINSTALL_TRACK: {
        struct pte_track_request req;
        struct pte_track_entry *entry;
        unsigned long irq_flags;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        spin_lock_irqsave(&track_list_lock, irq_flags);
        entry = pte_find_by_handle(req.handle);
        if (!entry) {
            spin_unlock_irqrestore(&track_list_lock, irq_flags);
            return -EINVAL;
        }
        list_del(&entry->list);
        spin_unlock_irqrestore(&track_list_lock, irq_flags);

        pte_destroy_entry(entry);
        pr_debug(TAG "Uninstalled PTE track: handle=0x%llx\n", req.handle);
        ret = 1;
        break;
    }

    case CMD_PTE_GET_HIT: {
        struct pte_hit_info hit;
        struct pte_track_entry *entry;
        unsigned long irq_flags;

        if (copy_from_user(&hit, (void __user *)arg, sizeof(hit)))
            return -EFAULT;

        spin_lock_irqsave(&track_list_lock, irq_flags);
        entry = pte_find_by_handle(hit.handle);
        spin_unlock_irqrestore(&track_list_lock, irq_flags);

        if (!entry)
            return -EINVAL;

        /* 如果没有命中数据，返回失败 */
        if (!entry->hit_ready)
            return -EAGAIN;

        spin_lock(&entry->lock);
        memcpy(&hit, &entry->hit, sizeof(hit));
        entry->hit_ready = false;
        spin_unlock(&entry->lock);

        if (copy_to_user((void __user *)arg, &hit, sizeof(hit)))
            return -EFAULT;

        ret = 1;
        break;
    }

    case CMD_PTE_RESUME: {
        struct pte_track_request req;
        struct pte_track_entry *entry;
        unsigned long irq_flags;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        spin_lock_irqsave(&track_list_lock, irq_flags);
        entry = pte_find_by_handle(req.handle);
        spin_unlock_irqrestore(&track_list_lock, irq_flags);

        if (!entry)
            return -EINVAL;

        /* 重新修改PTE */
        spin_lock(&entry->lock);
        if (!entry->suspended) {
            /* 如果未暂停，可能是之前命中了需要重新安装 */
            ret = pte_modify_for_track(entry);
        } else {
            entry->suspended = false;
            ret = pte_modify_for_track(entry);
        }
        spin_unlock(&entry->lock);

        if (ret < 0)
            return ret;

        pr_debug(TAG "Resumed PTE track: handle=0x%llx\n", req.handle);
        ret = 1;
        break;
    }

    case CMD_PTE_SET_REG_MODIFY: {
        struct pte_track_entry *entry;
        uint32_t config_count;
        unsigned long irq_flags;
        void __user *user_configs;
        size_t config_size;
        struct perf_request req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        /* req.src_buf 指向 PTE_REG_MODIFY_BATCH */
        user_configs = (void __user *)req.src_buf;
        if (!user_configs || req.buf_size < sizeof(struct pte_reg_modify_batch))
            return -EINVAL;

        /* 读取batch头部获取handle和config_count */
        struct pte_reg_modify_batch batch_hdr;
        if (copy_from_user(&batch_hdr, user_configs, sizeof(batch_hdr)))
            return -EFAULT;

        config_count = batch_hdr.config_count;
        if (config_count > MAX_REG_MODIFY)
            config_count = MAX_REG_MODIFY;

        config_size = config_count * sizeof(struct reg_modify_config);
        if (req.buf_size < sizeof(struct pte_reg_modify_batch) + config_size)
            return -EINVAL;

        spin_lock_irqsave(&track_list_lock, irq_flags);
        entry = pte_find_by_handle(batch_hdr.handle);
        spin_unlock_irqrestore(&track_list_lock, irq_flags);

        if (!entry)
            return -EINVAL;

        spin_lock(&entry->lock);
        memset(entry->reg_configs, 0, sizeof(entry->reg_configs));
        if (copy_from_user(entry->reg_configs,
                           user_configs + sizeof(struct pte_reg_modify_batch),
                           config_size)) {
            spin_unlock(&entry->lock);
            return -EFAULT;
        }
        entry->reg_config_count = config_count;
        spin_unlock(&entry->lock);

        pr_debug(TAG "Set %u reg modify configs for handle 0x%llx\n",
                config_count, batch_hdr.handle);
        ret = 1;
        break;
    }

    case CMD_PTE_CLEAR_REG_MODIFY: {
        struct pte_track_request req;
        struct pte_track_entry *entry;
        unsigned long irq_flags;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        spin_lock_irqsave(&track_list_lock, irq_flags);
        entry = pte_find_by_handle(req.handle);
        spin_unlock_irqrestore(&track_list_lock, irq_flags);

        if (!entry)
            return -EINVAL;

        spin_lock(&entry->lock);
        entry->reg_config_count = 0;
        memset(entry->reg_configs, 0, sizeof(entry->reg_configs));
        spin_unlock(&entry->lock);

        ret = 1;
        break;
    }

    case CMD_PTE_SUSPEND: {
        struct pte_track_request req;
        struct pte_track_entry *entry;
        unsigned long irq_flags;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        spin_lock_irqsave(&track_list_lock, irq_flags);
        entry = pte_find_by_handle(req.handle);
        spin_unlock_irqrestore(&track_list_lock, irq_flags);

        if (!entry)
            return -EINVAL;

        spin_lock(&entry->lock);
        if (entry->installed) {
            ret = pte_restore_original(entry);
            if (ret == 0)
                entry->suspended = true;
        }
        spin_unlock(&entry->lock);

        if (ret < 0)
            return ret;

        pr_debug(TAG "Suspended PTE track: handle=0x%llx\n", req.handle);
        ret = 1;
        break;
    }

    case CMD_PTE_QUERY_PAGE: {
        struct pte_track_request req;
        struct task_struct *task;
        struct mm_struct *mm;
        pte_t *ptep;
        pte_t pte;
        int lookup_ret;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        if (req.pid <= 0)
            return -EINVAL;

        rcu_read_lock();
        task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
        if (!task) {
            rcu_read_unlock();
            return -ESRCH;
        }
        get_task_struct(task);
        rcu_read_unlock();

        mm = get_task_mm(task);
        put_task_struct(task);
        if (!mm)
            return -ESRCH;

        lookup_ret = pte_lookup_in_mm(mm, req.virt_addr & PAGE_MASK,
                                      &ptep, NULL, NULL, NULL, NULL);
        if (lookup_ret < 0) {
            mmput(mm);
            return lookup_ret;
        }

        pte = *ptep;
        req.page_pa = pte_pfn(pte) << PAGE_SHIFT;
        req.page_size = PAGE_SIZE;

        spinlock_t *ptl = pte_lockptr(mm, NULL);
        pte_unmap_unlock(ptep, ptl);
        mmput(mm);

        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;

        ret = 1;
        break;
    }

    default:
        pr_warn(TAG "Unknown ioctl: 0x%x\n", cmd);
        return -ENOTTY;
    }

    return ret;
}

/* ==================== 文件操作 ==================== */

static const struct file_operations driver_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = driver_ioctl,
    .compat_ioctl   = driver_ioctl,
};

static struct miscdevice misc_dev = {
    .minor  = MISC_DYNAMIC_MINOR,
    .name   = DEVICE_NAME,
    .fops   = &driver_fops,
    .mode   = 0666,
};

/* ==================== kprobe 管理 ==================== */

/*
 * 使用kprobe获取 kallsyms_lookup_name 的地址
 * 因为在新内核中该函数可能不导出
 */
static int resolve_kallsyms(void)
{
    struct kprobe kp;
    int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    /* 6.6: kallsyms_lookup_name 未导出，用 kprobe 按名解析 */
    /*
     * CFI严格模式下 register_kprobe() 触发 KCFI 校验失败 → panic 重启。
     * 此 kprobe 仅解析 fpsimd_save_state_ptr，而该指针并未被实际使用，
     * 故整体注释掉以隔离崩溃点（KCFI Fatal 元凶）。
     * fpsimd_save_state_ptr 保留声明但不再赋值，不影响其他逻辑。
     */
    (void)kp; (void)ret;
    fpsimd_save_state_ptr = NULL;
    pr_debug(TAG "resolve_kallsyms: kprobe disabled (CFI-strict safe), fpsimd ptr NULL\n");
#else
    /* 老内核直接可用 */
    kallsyms_lookup_name_ptr = (void *)kallsyms_lookup_name;
#endif
    if (!kallsyms_lookup_name_ptr) {
        pr_warn(TAG "kallsyms_lookup_name not available, "
                "some features may be limited\n");
    }
    return 0;
}

static int register_fault_probe(void)
{
    int ret;

    memset(&kp_do_page_fault, 0, sizeof(kp_do_page_fault));
    kp_do_page_fault.symbol_name = "do_page_fault";
    kp_do_page_fault.pre_handler = pte_page_fault_pre_handler;

    ret = register_kprobe(&kp_do_page_fault);
    if (ret < 0) {
        pr_err(TAG "Failed to register kprobe on do_page_fault: %d\n", ret);
        pr_warn(TAG "PTE追踪将无法拦截缺页！\n");
        return ret;
    }

    kprobe_registered = true;
    pr_debug(TAG "kprobe registered on do_page_fault at %p\n",
            kp_do_page_fault.addr);
    return 0;
}

static void unregister_fault_probe(void)
{
    if (kprobe_registered) {
        unregister_kprobe(&kp_do_page_fault);
        kprobe_registered = false;
        pr_debug(TAG "kprobe unregistered\n");
    }
}

/* ==================== 兼容层：不同内核版本的差异处理 ==================== */

/*
 * ARM64 flush_tlb_user_page 包装
 * 不同内核版本API可能不同
 */
static inline void driver_flush_tlb_user(struct vm_area_struct *vma,
                                          unsigned long addr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    flush_tlb_page(vma, addr);
#else
    if (vma) {
        flush_tlb_page(vma, addr);
    } else {
        /* 全局刷新（备用） */
        flush_tlb_all();
    }
#endif
}

#ifndef __flush_tlb_user_page
#define __flush_tlb_user_page(vma, addr) driver_flush_tlb_user(vma, addr)
#endif

/*
 * 对于不支持某些API的古老内核提供备用实现
 */
#ifndef TIF_FOREIGN_FPSTATE
#define TIF_FOREIGN_FPSTATE TIF_FOREIGN_FPSTATE
#endif

/* ==================== 模块 init/exit ==================== */

static bool module_hidden = false;

/*
 * 隐藏模块：从内核 modules 链表与 sysfs 中摘除，使
 *   - lsmod / /proc/modules  看不到
 *   - /sys/module/<name>     看不到
 * 但 misc 设备节点(file_operations)仍有效，因此用户态 open+ioctl 不受影响。
 * 注意：隐藏后 rmmod 无法再通过模块名卸载（需驱动自身注销或重启恢复）。
 */
static void hide_module(void)
{
    struct module *mod = THIS_MODULE;

    if (module_hidden)
        return;

    /* 摘除 /sys/module/<name> 的 kobject 表示 */
    if (mod->mkobj.kobj.parent) {
        kobject_del(&mod->mkobj.kobj);
        kobject_put(&mod->mkobj.kobj);
    }

    /* 摘除 kernel modules 链表节点：lsmod、/proc/modules 即不可见 */
    list_del_init(&mod->list);

    /* 置标志，防重复摘除 */
    module_hidden = true;
}

static int __init pte_driver_init(void)
{
    int ret;

    /* 初始化追踪链表 */
    INIT_LIST_HEAD(&track_list);

    /* 生成随机节点名（每次 insmod 不同，避免固定设备节点特征） */
    rand_dev_name();

    /* 解析符号 */
    resolve_kallsyms();

    /* 注册misc设备（.name 已指向随机名 buffer） */
    ret = misc_register(&misc_dev);
    if (ret) {
        return ret;
    }
    misc_dev_ptr = &misc_dev;

    /* 注册成功后隐藏模块以对抗检测 */
    hide_module();

#ifdef PTE_ENABLE_FAULT_PROBE
    ret = register_fault_probe();
    if (ret < 0)
        pr_warn(TAG "fault interception unavailable\n");
#else
    pr_debug(TAG "fault probe disabled\n");
#endif

    pr_debug(TAG "driver ready\n");
    return 0;
}
static void __exit pte_driver_exit(void)
{
    struct pte_track_entry *entry, *tmp;

    /* 注销kprobe */
    unregister_fault_probe();

    /* 清理所有追踪条目 */
    list_for_each_entry_safe(entry, tmp, &track_list, list) {
        pr_debug(TAG "Cleanup: removing handle 0x%llx\n", entry->handle);
        list_del(&entry->list);
        pte_destroy_entry(entry);
    }

    /* 注销misc设备 */
    if (misc_dev_ptr) {
        misc_deregister(&misc_dev);
        misc_dev_ptr = NULL;
    }

    pr_info(TAG "PTE Tracking Driver exited\n");
}

module_init(pte_driver_init);
module_exit(pte_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PTE Driver");
MODULE_DESCRIPTION("ARM64 PTE-based Code Tracking Driver");
MODULE_VERSION("2.0.0");