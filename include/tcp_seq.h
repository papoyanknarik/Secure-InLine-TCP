#ifndef TCP_SEQ_H
#define TCP_SEQ_H

#include <stdint.h>
#include <stddef.h>

#define TCP_MAX_SEGMENTS 1024

typedef struct {
    uint32_t original_seq;
    uint32_t translated_seq;
    int64_t offset;
} TcpSeqMapping;

typedef struct {
    uint32_t original_seq;
    uint32_t translated_seq;
    uint32_t original_length;
    uint32_t encrypted_length;
} TcpSegmentMapping;

typedef struct {
    TcpSegmentMapping entries[TCP_MAX_SEGMENTS];
    size_t segment_count;
} TcpSegmentTable;

typedef enum {
    TCP_SEGMENT_ERROR = -1,
    TCP_SEGMENT_NEW = 0,
    TCP_SEGMENT_RETRANSMISSION = 1,
    TCP_SEGMENT_OVERLAP = 2
} TcpSegmentStatus;

typedef enum {
    TCP_ACK_UNMAPPED = 0,
    TCP_ACK_MAPPED = 1
} TcpAckStatus;

uint32_t tcp_translate_seq(uint32_t original_seq, int64_t offset);

int tcp_segment_mapping_init(
    TcpSegmentMapping *mapping,
    uint32_t original_seq,
    uint32_t translated_seq,
    uint32_t original_length,
    uint32_t encrypted_length
);

uint32_t tcp_segment_original_end(const TcpSegmentMapping *mapping);
uint32_t tcp_segment_translated_end(const TcpSegmentMapping *mapping);

const TcpSegmentMapping *tcp_find_segment(
    const TcpSegmentMapping *segments,
    size_t segment_count,
    uint32_t sequence_number
);

const TcpSegmentMapping *tcp_find_exact_segment(
    const TcpSegmentMapping *segments,
    size_t segment_count,
    uint32_t sequence_number,
    uint32_t data_length
);

int tcp_segments_overlap(
    uint32_t first_seq,
    uint32_t first_len,
    uint32_t second_seq,
    uint32_t second_len
);

TcpSegmentStatus tcp_segment_table_add(
    TcpSegmentTable *table,
    uint32_t original_seq,
    uint32_t original_length,
    uint32_t encrypted_length,
    TcpSegmentMapping *result
);

TcpAckStatus tcp_translate_ack(
    const TcpSegmentTable *table,
    uint32_t translated_ack,
    uint32_t *original_ack
);

#endif
