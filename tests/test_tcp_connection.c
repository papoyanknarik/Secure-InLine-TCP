
#include "tcp_connection.h"

#include <assert.h>
#include <stdio.h>

int main(void) {

    TcpConnectionTable table = {0};

    TcpFlowKey flow1 = {
        .source_ip = 0x0A000101,
        .destination_ip = 0x0A000302,
        .source_port = 45000,
        .destination_port = 5000
    };

    TcpFlowKey flow2 = {
        .source_ip = 0x0A000101,
        .destination_ip = 0x0A000302,
        .source_port = 45001,
        .destination_port = 5000
    };

    assert(tcp_flow_equal(&flow1, &flow1) == 1);
    assert(tcp_flow_equal(&flow1, &flow2) == 0);

    TcpConnection *connection1 =
        tcp_connection_add(&table, &flow1);

    assert(connection1 != NULL);
    assert(connection1->status == TCP_CONN_NEW);
    assert(connection1->handshake_state == TCP_HANDSHAKE_WAIT_SYN);
    assert(table.connection_count == 1);

    assert(tcp_connection_find(&table, &flow1) == connection1);
    assert(tcp_connection_add(&table, &flow1) == connection1);

    TcpConnection *connection2 =
        tcp_connection_add(&table, &flow2);

    assert(connection2 != NULL);
    assert(connection2 != connection1);
    assert(table.connection_count == 2);

    TcpFlowKey reverse_flow = {
        .source_ip = 0x0A000302,
        .destination_ip = 0x0A000101,
        .source_port = 5000,
        .destination_port = 45000
    };

    assert(tcp_flow_reverse_equal(&flow1, &reverse_flow) == 1);
    assert(tcp_flow_reverse_equal(&flow1, &flow2) == 0);

    assert(tcp_connection_find_bidirectional(
        &table, &reverse_flow
    ) == connection1);

    assert(tcp_connection_direction(
        connection1, &flow1
    ) == TCP_DIRECTION_FORWARD);

    assert(tcp_connection_direction(
        connection1, &reverse_flow
    ) == TCP_DIRECTION_REVERSE);

    TcpDirectionState *forward =
        tcp_connection_direction_state(connection1, &flow1);

    TcpDirectionState *reverse =
        tcp_connection_direction_state(connection1, &reverse_flow);

    assert(forward != NULL);
    assert(reverse != NULL);
    assert(forward != reverse);

    forward->initial_seq = 1000;
    reverse->initial_seq = 5000;

    assert(connection1->forward.initial_seq == 1000);
    assert(connection1->reverse.initial_seq == 5000);

    TcpSegmentMapping mapping;

    assert(tcp_segment_table_add(
        &forward->segments, 1000, 100, 128, &mapping
    ) == TCP_SEGMENT_NEW);

    assert(forward->segments.segment_count == 1);
    assert(reverse->segments.segment_count == 0);

    /* TCP three-way handshake */

    assert(tcp_connection_process_event(
        connection1, TCP_EVENT_SYN
    ) == 1);

    assert(connection1->status == TCP_CONN_NEW);
    assert(connection1->handshake_state ==
           TCP_HANDSHAKE_WAIT_SYN_ACK);

    assert(tcp_connection_process_event(
        connection1, TCP_EVENT_SYN_ACK
    ) == 1);

    assert(connection1->status == TCP_CONN_NEW);
    assert(connection1->handshake_state ==
           TCP_HANDSHAKE_WAIT_ACK);

    assert(tcp_connection_process_event(
        connection1, TCP_EVENT_ACK
    ) == 1);

    assert(connection1->status == TCP_CONN_ESTABLISHED);
    assert(connection1->handshake_state ==
           TCP_HANDSHAKE_COMPLETE);

    /* Invalid event order */

    assert(tcp_connection_process_event(
        connection2, TCP_EVENT_ACK
    ) == 0);

    assert(connection2->status == TCP_CONN_NEW);

    /* FIN closes connection */

    assert(tcp_connection_process_event(
        connection1, TCP_EVENT_FIN
    ) == 1);

    assert(connection1->status == TCP_CONN_CLOSED);

    assert(tcp_connection_process_event(
        connection1, TCP_EVENT_ACK
    ) == 0);

    /* RST closes connection */

    assert(tcp_connection_process_event(
        connection2, TCP_EVENT_RST
    ) == 1);

    assert(connection2->status == TCP_CONN_CLOSED);

    assert(tcp_connection_process_event(
        connection2, TCP_EVENT_SYN
    ) == 0);

    printf("TCP connection tests completed successfully!\n");

    return 0;
}
