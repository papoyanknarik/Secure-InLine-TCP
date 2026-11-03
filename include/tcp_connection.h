#ifndef TCP_CONNECTION_H
#define TCP_CONNECTION_H

#include <stddef.h>
#include <stdint.h>
#include "tcp_seq.h"

#define TCP_MAX_CONNECTIONS 128

typedef struct {
    uint32_t source_ip;
    uint32_t destination_ip;
    uint16_t source_port;
    uint16_t destination_port;
} TcpFlowKey;

typedef enum {
    TCP_CONN_NEW,
    TCP_CONN_ESTABLISHED,
    TCP_CONN_CLOSED
} TcpConnectionStatus;

typedef enum {
    TCP_HANDSHAKE_WAIT_SYN,
    TCP_HANDSHAKE_WAIT_SYN_ACK,
    TCP_HANDSHAKE_WAIT_ACK,
    TCP_HANDSHAKE_COMPLETE
} TcpHandshakeState;

typedef struct {
    TcpSegmentTable segments;
    uint32_t initial_seq;
    uint32_t last_ack;
} TcpDirectionState;

typedef struct {
    TcpFlowKey key;
    TcpConnectionStatus status;
    TcpHandshakeState handshake_state;
    TcpDirectionState forward;
    TcpDirectionState reverse;
} TcpConnection;

typedef struct {
    TcpConnection connections[TCP_MAX_CONNECTIONS];
    size_t connection_count;
} TcpConnectionTable;

int tcp_flow_equal(
    const TcpFlowKey *first,
    const TcpFlowKey *second
);

TcpConnection *tcp_connection_find(
    TcpConnectionTable *table,
    const TcpFlowKey *key
);

TcpConnection *tcp_connection_add(
    TcpConnectionTable *table,
    const TcpFlowKey *key
);

int tcp_flow_reverse_equal(
    const TcpFlowKey *first,
    const TcpFlowKey *second
);

TcpConnection *tcp_connection_find_bidirectional(
    TcpConnectionTable *table,
    const TcpFlowKey *key
);

typedef enum {
    TCP_DIRECTION_INVALID = -1,
    TCP_DIRECTION_FORWARD = 0,
    TCP_DIRECTION_REVERSE = 1
} TcpDirection;

TcpDirection tcp_connection_direction(
    const TcpConnection *connection,
    const TcpFlowKey *key
);

TcpDirectionState *tcp_connection_direction_state(
    TcpConnection *connection,
    const TcpFlowKey *key
);

typedef enum {
    TCP_EVENT_SYN,
    TCP_EVENT_SYN_ACK,
    TCP_EVENT_ACK,
    TCP_EVENT_FIN,
    TCP_EVENT_RST
} TcpConnectionEvent;

int tcp_connection_process_event(
    TcpConnection *connection,
    TcpConnectionEvent event
);

#endif
