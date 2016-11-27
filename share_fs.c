#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <asm/syscall.h>
#include <linux/string.h>

typedef int (*handler_pre)(struct kprobe *p, struct pt_regs *regs);
typedef void (*handler_post)(struct kprobe *p, struct pt_regs *regs, unsigned long flags);
typedef int (*handler_fault)(struct kprobe *p, struct pt_regs *regs, int trapnr);

int pre_do_filp_open(struct kprobe *p, struct pt_regs *regs);
void post_do_filp_open(struct kprobe *p, struct pt_regs *regs, unsigned long flags);
int fault_do_filp_open(struct kprobe *p, struct pt_regs *regs, int trapnr);
int pre_open(struct kprobe *p, struct pt_regs *regs);
void post_open(struct kprobe *p, struct pt_regs *regs, unsigned long flags);
int fault_open(struct kprobe *p, struct pt_regs *regs, int trapnr);
int pre_openat(struct kprobe *p, struct pt_regs *regs);
void post_openat(struct kprobe *p, struct pt_regs *regs, unsigned long flags);
int fault_openat(struct kprobe *p, struct pt_regs *regs, int trapnr);

#define MZ_KPROBE(name)									\
    static struct kprobe kp_##name = {							\
        .pre_handler = pre_##name,							\
        .post_handler = post_##name,							\
        .fault_handler = fault_##name,							\
        .addr = NULL,									\
    };

MZ_KPROBE(do_filp_open) 
MZ_KPROBE(open) 
MZ_KPROBE(openat) 

struct mz_kprobe {
    char *name;
    struct kprobe *kp;
};

static struct timeval start, end;
static int schedule_counter = 0;

int pre_do_filp_open(struct kprobe *p, struct pt_regs *regs)
{
    printk("current task onCPU#%d: %s (before scheduling), preempt_count = %d\n", smp_processor_id(),current->comm, preempt_count());
    printk("before %s: arg:%016lx, filename:%s\n", __func__, regs->si, (char *)(regs->si));
    unsigned long args;
    syscall_get_arguments(current, regs, 2, 1, &args);
    printk("after %s: arg:%016lx, filename:%s\n", __func__, args, (char*)args);
    schedule_counter++;
    return 0;
}

void post_do_filp_open(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    printk("current task onCPU#%d: %s (after scheduling), preempt_count = %d\n", smp_processor_id(),current->comm, preempt_count());
}

int fault_do_filp_open(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    printk("A fault happenedduring probing.\n");
    return 0;
}

int pre_open(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long args;
    printk("current task onCPU#%d: %s (before scheduling), preempt_count = %d\n", smp_processor_id(),current->comm, preempt_count());
    printk("before %s: arg:%016lx, filename:%s\n", __func__, regs->si, (char *)(regs->si));
    syscall_get_arguments(current, regs, 2, 1, &args);
    printk("after %s: arg:%016lx, filename:%s\n", __func__, args, (char*)args);
    schedule_counter++;
    return 0;
}

void post_open(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    printk("current task onCPU#%d: %s (after scheduling), preempt_count = %d\n", smp_processor_id(),current->comm, preempt_count());
}

int fault_open(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    printk("A fault happenedduring probing.\n");
    return 0;
}

int pre_openat(struct kprobe *p, struct pt_regs *regs)
{
    printk("current task onCPU#%d: %s (before scheduling), preempt_count = %d\n", smp_processor_id(),current->comm, preempt_count());
    printk("before %s: arg:%016lx, filename:%s\n", __func__, regs->si, (char *)(regs->si));
    unsigned long args;
    syscall_get_arguments(current, regs, 2, 1, &args);
    printk("after %s: arg:%016lx, filename:%s\n", __func__, args, (char*)args);
    schedule_counter++;
    return 0;
}

void post_openat(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    printk("current task onCPU#%d: %s (after scheduling), preempt_count = %d\n", smp_processor_id(),current->comm, preempt_count());
}

int fault_openat(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    printk("A fault happenedduring probing.\n");
    return 0;
}

static struct mz_kprobe mz_kprobes[] = {
    {"open", (struct kprobe*)(&kp_open)},
    {"openat", (struct kprobe*)(&kp_openat)},
   // {"do_filp_open", (struct kprobe*)(&kp_do_filp_open)},
};	

static int register_mz_kprobes(void)
{
    int ret;

    unsigned int len = sizeof(mz_kprobes)/sizeof(struct mz_kprobe);
    int i;
    printk("register_mz_krobes: len = %u\n", len);
    for (i = 0; i < len; i++) {
    	printk("%s kproberegistered\n", mz_kprobes[i].name);
	char name[50];
        strcat(name, "sys_");
	strcat(name, mz_kprobes[i].name);
	printk("name:%s\n", name);
	mz_kprobes[i].kp->symbol_name = name;//(kprobe_opcode_t*)kallsyms_lookup_name(mz_kprobes[i].name);
	if (!mz_kprobes[i].kp->addr) {
	    printk("Couldn't get the address of schedule.\n");
	    //return -1;
	}
	ret = register_kprobe(mz_kprobes[i].kp);
	if (ret < 0) {
	    printk("register_kprobe failed, returned %d\n", ret);
	    return -1;
	}

    }
    return 0;
}

static int unregister_mz_kprobes(void)
{
    unsigned int len = sizeof(mz_kprobes)/sizeof(struct mz_kprobe);
    int i;
    for (i = 0; i < len; i++) {
	unregister_kprobe(mz_kprobes[i].kp);
    }
    return 0;
}

static int __init share_init(void)
{
    //register_kprobe_handler("schedule");
    register_mz_kprobes();
    do_gettimeofday(&start);

    return 0;
}

static void __exit share_exit(void)
{
    unregister_mz_kprobes();
    do_gettimeofday(&end);
    printk("Scheduling timesis %d during of %ld milliseconds.\n", schedule_counter, ((end.tv_sec -start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec))/1000);
    printk("kprobeunregistered\n");
}

module_init(share_init);
module_exit(share_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("jalor");
