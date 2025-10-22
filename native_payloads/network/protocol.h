/*
 * Network Protocol Header
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "../core/config.h"

// Protocol version and magic
#define PROTOCOL_VERSION 0x01
#define PROTOCOL_MAGIC 0xDEADC0DE

// Packet types
typedef enum {
    PACKET_HELLO = 0x01,
    PACKET_COMMAND = 0x02,
    PACKET_RESPONSE = 0x03,
    PACKET_DATA = 0x04,
    PACKET_HEARTBEAT = 0x05,
    PACKET_ERROR = 0x06,
    PACKET_BYE = 0x07
} packet_type_t;

// Packet header structure
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t length;
    uint32_t checksum;
    uint8_t iv[16];
} packet_header_t;

// Packet structure
typedef struct {
    packet_header_t header;
    uint8_t* data;
    size_t data_len;
} packet_t;

// Connection context
typedef struct {
    int socket;
    uint8_t aes_key[32];
    uint8_t session_id[16];
    uint32_t seq_send;
    uint32_t seq_recv;
    int connected;
    char server_host[256];
    uint16_t server_port;
} connection_t;

// Connection management
int protocol_connect(connection_t* conn, const char* host, uint16_t port);
int protocol_disconnect(connection_t* conn);
int protocol_reconnect(connection_t* conn);
int protocol_handshake(connection_t* conn);

// Packet operations
int protocol_send_packet(connection_t* conn, packet_type_t type, 
                        const uint8_t* data, size_t len);
int protocol_recv_packet(connection_t* conn, packet_t* packet);
void protocol_free_packet(packet_t* packet);

// High-level operations
int protocol_send_response(connection_t* conn, uint32_t seq,
                          const uint8_t* data, size_t len);
int protocol_send_error(connection_t* conn, uint32_t seq, 
                       const char* error_msg);
int protocol_send_heartbeat(connection_t* conn);

// Utilities
uint32_t protocol_crc32(const uint8_t* data, size_t len);
int protocol_encrypt_data(uint8_t* data, size_t len, 
                         const uint8_t* key, const uint8_t* iv);
int protocol_decrypt_data(uint8_t* data, size_t len,
                         const uint8_t* key, const uint8_t* iv);

// Socket operations (platform-specific)
int socket_init(void);
void socket_cleanup(void);
int socket_create(void);
int socket_connect(int sock, const char* host, uint16_t port);
int socket_send(int sock, const uint8_t* data, size_t len);
int socket_recv(int sock, uint8_t* buffer, size_t len);
int socket_close(int sock);
int socket_set_timeout(int sock, int timeout_ms);

// Simplified protocol functions for main.c
int protocol_send(int sock, const uint8_t* data, size_t len);
int protocol_receive(int sock, uint8_t* buffer, size_t* len);
int protocol_handshake_simple(int sock);

#endif // PROTOCOL_H