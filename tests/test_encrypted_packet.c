#include "packet_parser.h"
#include "payload_crypto.h"
#include "checksum.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TCP_IP_HEADER_SIZE 40
#define PACKET_BUFFER_SIZE 512

static void put16(unsigned char *data, uint16_t number) {
    data[0] = (unsigned char)(number >> 8);
    data[1] = (unsigned char)(number & 0xFF);
}

static void put32(unsigned char *data, uint32_t number) {
    data[0] = (unsigned char)(number >> 24);
    data[1] = (unsigned char)(number >> 16);
    data[2] = (unsigned char)(number >> 8);
    data[3] = (unsigned char)(number & 0xFF);
}

static void refresh_checksums(unsigned char *data, size_t size) {
    put16(data + 10, 0);
    put16(data + 36, 0);

    put16(data + 10, ipv4_checksum(data, 20));
    put16(data + 36, tcp_checksum(data, size));
}

static void create_tcp_packet(
    unsigned char *data,
    const unsigned char *content,
    size_t content_size
) {
    size_t total_size = TCP_IP_HEADER_SIZE + content_size;

    memset(data, 0, total_size);

    data[0] = 0x45;
    put16(data + 2, (uint16_t)total_size);
    data[8] = 64;
    data[9] = 6;

    put32(data + 12, 0x0A000101);
    put32(data + 16, 0x0A000302);

    put16(data + 20, 45000);
    put16(data + 22, 5000);

    put32(data + 24, 2000);
    data[32] = 0x50;
    data[33] = 0x18;
    put16(data + 34, 4096);

    memcpy(data + TCP_IP_HEADER_SIZE, content, content_size);

    refresh_checksums(data, total_size);
}

int main(void) {
    unsigned char secret_key[AES_KEY_SIZE] = {0};
    unsigned char nonce_prefix[4] = {5, 10, 15, 20};

    for (size_t j = 0; j < AES_KEY_SIZE; j++) {
        secret_key[j] = (unsigned char)(j + 10);
    }

    NonceManager nonce_state = {0};
    assert(nonce_manager_init(&nonce_state, nonce_prefix) == 1);

    const unsigned char text[] = "TCP Payload Integration Check";
    size_t text_size = strlen((const char *)text);

    unsigned char packet[PACKET_BUFFER_SIZE] = {0};
    unsigned char secured_packet[PACKET_BUFFER_SIZE] = {0};
    unsigned char decoded_packet[PACKET_BUFFER_SIZE] = {0};

    size_t packet_size = TCP_IP_HEADER_SIZE + text_size;

    create_tcp_packet(packet, text, text_size);

    ParsedPacket initial_data = {0};

    assert(parse_tcp_packet(
        packet,
        packet_size,
        &initial_data
    ) == 1);

    assert(initial_data.payload_len == text_size);
    assert(memcmp(initial_data.payload, text, text_size) == 0);

    printf("TCP packet parsing test: PASSED\n");

    memcpy(secured_packet, packet, TCP_IP_HEADER_SIZE);

    size_t secured_data_size = 0;

    assert(encrypt_payload(
        secret_key,
        &nonce_state,
        initial_data.payload,
        initial_data.payload_len,
        secured_packet + TCP_IP_HEADER_SIZE,
        PACKET_BUFFER_SIZE - TCP_IP_HEADER_SIZE,
        &secured_data_size
    ) == 1);

    size_t secured_packet_size =
        TCP_IP_HEADER_SIZE + secured_data_size;

    assert(secured_packet_size <= PACKET_BUFFER_SIZE);
    assert(secured_packet_size <= UINT16_MAX);

    put16(secured_packet + 2, (uint16_t)secured_packet_size);

    refresh_checksums(secured_packet, secured_packet_size);

    ParsedPacket secured_data = {0};

    assert(parse_tcp_packet(
        secured_packet,
        secured_packet_size,
        &secured_data
    ) == 1);

    assert(secured_data.payload_len == text_size + PAYLOAD_OVERHEAD);

    printf("Packet encryption test: PASSED\n");

    memcpy(decoded_packet, secured_packet, TCP_IP_HEADER_SIZE);

    size_t decoded_size = 0;

    assert(decrypt_payload(
        secret_key,
        secured_data.payload,
        secured_data.payload_len,
        decoded_packet + TCP_IP_HEADER_SIZE,
        PACKET_BUFFER_SIZE - TCP_IP_HEADER_SIZE,
        &decoded_size
    ) == 1);

    assert(decoded_size == text_size);

    size_t final_packet_size = TCP_IP_HEADER_SIZE + decoded_size;

    put16(decoded_packet + 2, (uint16_t)final_packet_size);

    refresh_checksums(decoded_packet, final_packet_size);

    ParsedPacket final_data = {0};

    assert(parse_tcp_packet(
        decoded_packet,
        final_packet_size,
        &final_data
    ) == 1);

    assert(final_data.payload_len == text_size);

    assert(memcmp(
        final_data.payload,
        text,
        text_size
    ) == 0);

    assert(final_packet_size == packet_size);

    printf("Packet decryption and restoration: PASSED\n");

    secured_packet[TCP_IP_HEADER_SIZE + GCM_NONCE_SIZE] ^= 0x01;

    size_t invalid_size = 0;

    assert(decrypt_payload(
        secret_key,
        secured_packet + TCP_IP_HEADER_SIZE,
        secured_data_size,
        decoded_packet + TCP_IP_HEADER_SIZE,
        PACKET_BUFFER_SIZE - TCP_IP_HEADER_SIZE,
        &invalid_size
    ) != 1);

    printf("Modified packet rejection: PASSED\n");
    printf("All TCP packet integration tests passed\n");

    return 0;
}
