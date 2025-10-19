#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

// Test minimal C2 connection to debug the issue

int main() {
    printf("[DEBUG] Starting C2 connection test...\n");
    
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("[ERROR] Socket creation failed: %s\n", strerror(errno));
        return 1;
    }
    printf("[OK] Socket created: %d\n", sock);
    
    // Setup address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    
    // Test different addresses
    const char* test_hosts[] = {"127.0.0.1", "localhost", NULL};
    
    for (int i = 0; test_hosts[i]; i++) {
        printf("\n[TEST] Trying %s:4433...\n", test_hosts[i]);
        
        if (strcmp(test_hosts[i], "localhost") == 0) {
            addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        } else {
            addr.sin_addr.s_addr = inet_addr(test_hosts[i]);
        }
        
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            printf("[ERROR] Invalid address\n");
            continue;
        }
        
        // Try to connect
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            printf("[SUCCESS] Connected to %s!\n", test_hosts[i]);
            
            // Send test data
            const char* msg = "HELLO_C2\n";
            if (send(sock, msg, strlen(msg), 0) > 0) {
                printf("[SUCCESS] Sent: %s", msg);
            }
            
            close(sock);
            return 0;
        } else {
            printf("[FAIL] Connect failed: %s (errno=%d)\n", strerror(errno), errno);
            
            // Create new socket for next attempt
            close(sock);
            sock = socket(AF_INET, SOCK_STREAM, 0);
        }
    }
    
    close(sock);
    return 1;
}