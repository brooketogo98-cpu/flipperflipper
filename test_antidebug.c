#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int detect_debugger_test() {
    // Check /proc/self/status for TracerPid
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        int len = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (len > 0) {
            buf[len] = 0;
            char* tracer = strstr(buf, "TracerPid:");
            if (tracer) {
                tracer += 10;
                while (*tracer == ' ' || *tracer == '\t') tracer++;
                printf("TracerPid value: '%c'\n", *tracer);
                if (*tracer != '0') {
                    return 1;  // Being traced
                }
            }
        }
    }
    return 0;
}

int detect_sandbox_test() {
    // Check CPU count
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    printf("CPU cores: %ld\n", nprocs);
    if (nprocs <= 1) {
        return 1;
    }
    
    // Check memory
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    long total_mem = pages * page_size;
    printf("Total memory: %ld MB\n", total_mem / (1024*1024));
    if (total_mem < 2L * 1024 * 1024 * 1024) { // Less than 2GB
        return 1;
    }
    
    return 0;
}

int main() {
    printf("Testing anti-analysis checks...\n");
    
    if (detect_debugger_test()) {
        printf("DETECTED: Debugger present!\n");
    } else {
        printf("OK: No debugger detected\n");
    }
    
    if (detect_sandbox_test()) {
        printf("DETECTED: Sandbox environment!\n");
    } else {
        printf("OK: Not a sandbox\n");
    }
    
    return 0;
}