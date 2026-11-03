
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include "tcp_seq.h"

int main(void) {

    assert(tcp_translate_seq(1000, 128) == 1128);
    assert(tcp_translate_seq(1000, 0) == 1000);

    TcpSegmentMapping mapping;

    assert(tcp_segment_mapping_init(
        &mapping, 1000, 1000, 100, 128
    ) == 1);

    assert(mapping.original_seq == 1000);
    assert(mapping.translated_seq == 1000);
    assert(mapping.original_length == 100);
    assert(mapping.encrypted_length == 128);

    assert(tcp_segment_original_end(&mapping) == 1100);
    assert(tcp_segment_translated_end(&mapping) == 1128);

    const TcpSegmentMapping *found =
        tcp_find_segment(&mapping, 1, 1000);

    assert(found != NULL);
    assert(found->original_seq == 1000);

    const TcpSegmentMapping *exact =
        tcp_find_exact_segment(&mapping, 1, 1000, 100);

    assert(exact != NULL);

    const TcpSegmentMapping *partial =
        tcp_find_exact_segment(&mapping, 1, 1000, 50);

    assert(partial == NULL);

    assert(tcp_segments_overlap(1000, 100, 1050, 50) == 1);
    assert(tcp_segments_overlap(1000, 100, 1100, 100) == 0);
    assert(tcp_segments_overlap(1000, 100, 1200, 50) == 0);
    assert(tcp_segments_overlap(1000, 100, 1000, 100) == 1);
    assert(tcp_segments_overlap(1050, 50, 1000, 100) == 1);
    assert(tcp_segments_overlap(1000, 0, 1050, 50) == 0);
    assert(tcp_segments_overlap(UINT32_MAX - 9, 20, 0, 5) == 1);

    assert(tcp_segments_overlap(UINT32_MAX - 4, 10, 0, 5) == 1);
    assert(tcp_segments_overlap(0, 5, UINT32_MAX - 4, 10) == 1);
    assert(tcp_segments_overlap(UINT32_MAX - 4, 5, 0, 5) == 0);
    assert(tcp_segments_overlap(1000, 100, 900, 100) == 0);
    assert(tcp_segments_overlap(1000, 100, 999, 1) == 0);
    assert(tcp_segments_overlap(1000, 100, 0x80000000U, 100) == 0);
    assert(tcp_segments_overlap(0, 100, 0x80000000U, 100) == 0);

    TcpSegmentTable table = {0};
    TcpSegmentMapping current_entry;

    assert(tcp_segment_table_add(
        &table, 1000, 100, 128, &current_entry
    ) == TCP_SEGMENT_NEW);

    assert(current_entry.translated_seq == 1000);
    assert(table.segment_count == 1);

    assert(tcp_segment_table_add(
        &table, 1100, 100, 128, &current_entry
    ) == TCP_SEGMENT_NEW);

    assert(current_entry.translated_seq == 1128);
    assert(table.segment_count == 2);

    assert(tcp_segment_table_add(
        &table, 1000, 100, 128, &current_entry
    ) == TCP_SEGMENT_RETRANSMISSION);

    assert(current_entry.translated_seq == 1000);
    assert(table.segment_count == 2);

    assert(tcp_segment_table_add(
        &table, 1050, 50, 78, &current_entry
    ) == TCP_SEGMENT_OVERLAP);

    assert(table.segment_count == 2);

    TcpSegmentTable out_of_order = {0};
    TcpSegmentMapping out_entry;

    assert(tcp_segment_table_add(
        &out_of_order, 1100, 100, 128, &out_entry
    ) == TCP_SEGMENT_NEW);

    assert(tcp_segment_table_add(
        &out_of_order, 1000, 100, 128, &out_entry
    ) == TCP_SEGMENT_NEW);

    assert(out_of_order.entries[0].translated_seq == 1100);
    assert(out_of_order.entries[1].translated_seq == 1000);

    /* ACK translation tests */

    TcpSegmentTable ack_table = {0};
    TcpSegmentMapping ack_mapping;

    assert(tcp_segment_table_add(
        &ack_table, 1000, 100, 128, &ack_mapping
    ) == TCP_SEGMENT_NEW);

    uint32_t original_ack = 0;

    assert(tcp_translate_ack(
        &ack_table, 1000, &original_ack
    ) == TCP_ACK_UNMAPPED);

    assert(tcp_translate_ack(
        &ack_table, 1128, &original_ack
    ) == TCP_ACK_MAPPED);

    assert(original_ack == 1100);

    assert(tcp_translate_ack(
        NULL, 1128, &original_ack
    ) == TCP_ACK_UNMAPPED);

    assert(tcp_translate_ack(
        &ack_table, 1128, NULL
    ) == TCP_ACK_UNMAPPED);

    /* Sequence number wrap-around tests */

    TcpSegmentTable wrap_table = {0};
    TcpSegmentMapping wrap_segment;

    assert(tcp_segment_table_add(
        &wrap_table, UINT32_MAX - 15, 20, 48, &wrap_segment
    ) == TCP_SEGMENT_NEW);

    assert(tcp_translate_ack(
        &wrap_table, 32, &original_ack
    ) == TCP_ACK_MAPPED);

    assert(original_ack == 4);

    /* Recovery tests */

    TcpSegmentTable recovery_table = {0};
    TcpSegmentMapping recovery_mapping;

    assert(tcp_segment_table_add(
        &recovery_table, 1000, 100, 128, &recovery_mapping
    ) == TCP_SEGMENT_NEW);

    assert(tcp_segment_table_add(
        &recovery_table, 900, 100, 128, &recovery_mapping
    ) == TCP_SEGMENT_ERROR);

    assert(recovery_table.segment_count == 1);

    assert(tcp_segment_table_add(
        &recovery_table, 1100, 100, 128, &recovery_mapping
    ) == TCP_SEGMENT_NEW);

    assert(recovery_mapping.translated_seq == 1128);
    assert(recovery_table.segment_count == 2);

    printf("TCP sequence tests completed successfully!\n");

    return 0;
}

