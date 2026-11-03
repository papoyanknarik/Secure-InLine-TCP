#include "tcp_seq.h"

uint32_t tcp_translate_seq(
    uint32_t original_seq,
    int64_t offset
) {
    return original_seq + (uint32_t)offset;
}
int tcp_segment_mapping_init(
    TcpSegmentMapping *mapping,
    uint32_t original_seq,
    uint32_t translated_seq,
    uint32_t original_length,
    uint32_t encrypted_length
) {
    if (mapping == NULL || encrypted_length < original_length) {
        return 0;
    }

    mapping->original_seq = original_seq;
    mapping->translated_seq = translated_seq;
    mapping->original_length = original_length;
    mapping->encrypted_length = encrypted_length;

    return 1;
}
uint32_t tcp_segment_original_end(
    const TcpSegmentMapping *mapping
) {
    if (mapping == NULL) {
        return 0;
    }

    return mapping->original_seq + mapping->original_length;
}

uint32_t tcp_segment_translated_end(
    const TcpSegmentMapping *mapping
) {
    if (mapping == NULL) {
        return 0;
    }

    return mapping->translated_seq + mapping->encrypted_length;
}
const TcpSegmentMapping *tcp_find_segment(
    const TcpSegmentMapping *segments,
    size_t segment_count,
    uint32_t sequence_number
) {
    if (segments == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < segment_count; i++) {

        if (segments[i].original_seq == sequence_number) {
            return &segments[i];
        }
    }

    return NULL;
}
const TcpSegmentMapping *tcp_find_exact_segment(
    const TcpSegmentMapping *segments,
    size_t segment_count,
    uint32_t sequence_number,
    uint32_t data_length
) {
    if (segments == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < segment_count; i++) {

        if (segments[i].original_seq == sequence_number &&
            segments[i].original_length == data_length) {

            return &segments[i];
        }
    }

    return NULL;
}
int tcp_segments_overlap(
    uint32_t first_seq,
    uint32_t first_len,
    uint32_t second_seq,
    uint32_t second_len
) {
    if (first_len == 0 || second_len == 0) {
        return 0;
    }

    uint32_t first_distance = second_seq - first_seq;
    uint32_t second_distance = first_seq - second_seq;

    return first_distance < first_len ||
           second_distance < second_len;
}
TcpSegmentStatus tcp_segment_table_add(
    TcpSegmentTable *table,
    uint32_t original_seq,
    uint32_t original_length,
    uint32_t encrypted_length,
    TcpSegmentMapping *result
) {
    if (table == NULL || result == NULL ||
        original_length == 0 ||
        encrypted_length < original_length ||
        table->segment_count > TCP_MAX_SEGMENTS) {
        return TCP_SEGMENT_ERROR;
    }

    for (size_t i = 0; i < table->segment_count; i++) {

        const TcpSegmentMapping *current = &table->entries[i];

        if (current->original_seq == original_seq &&
            current->original_length == original_length &&
            current->encrypted_length == encrypted_length) {

            *result = *current;
            return TCP_SEGMENT_RETRANSMISSION;
        }

        if (tcp_segments_overlap(
                current->original_seq,
                current->original_length,
                original_seq,
                original_length)) {

            return TCP_SEGMENT_OVERLAP;
        }
    }

    if (table->segment_count == TCP_MAX_SEGMENTS) {
        return TCP_SEGMENT_ERROR;
    }

    uint32_t translated_seq = original_seq;
    uint32_t total_offset = 0;

    for (size_t i = 0; i < table->segment_count; i++) {

        const TcpSegmentMapping *current = &table->entries[i];

        if ((int32_t)(original_seq -
            tcp_segment_original_end(current)) >= 0) {

            total_offset += current->encrypted_length -
                            current->original_length;
        }
    }

    translated_seq += total_offset;

    TcpSegmentMapping *new_entry =
        &table->entries[table->segment_count];

    if (!tcp_segment_mapping_init(
            new_entry,
            original_seq,
            translated_seq,
            original_length,
            encrypted_length)) {

        return TCP_SEGMENT_ERROR;
    }

    table->segment_count++;

    *result = *new_entry;

    return TCP_SEGMENT_NEW;
}
