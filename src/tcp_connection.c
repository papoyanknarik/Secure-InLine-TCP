
#include "tcp_connection.h"

#include <string.h>

int tcp_flow_equal(
    const TcpFlowKey *first,
    const TcpFlowKey *second
) {
    if (first == NULL || second == NULL) {
        return 0;
    }

    return first->source_ip == second->source_ip &&
           first->destination_ip == second->destination_ip &&
           first->source_port == second->source_port &&
           first->destination_port == second->destination_port;
}

TcpConnection *tcp_connection_find(
    TcpConnectionTable *table,
    const TcpFlowKey *key
) {
    if (table == NULL || key == NULL ||
        table->connection_count > TCP_MAX_CONNECTIONS) {
        return NULL;
    }

    for (size_t i = 0; i < table->connection_count; i++) {
        if (tcp_flow_equal(&table->connections[i].key, key)) {
            return &table->connections[i];
        }
    }

    return NULL;
}

TcpConnection *tcp_connection_add(
    TcpConnectionTable *table,
    const TcpFlowKey *key
) {
    if (table == NULL || key == NULL ||
        table->connection_count > TCP_MAX_CONNECTIONS) {
        return NULL;
    }

    TcpConnection *existing = tcp_connection_find(table, key);

    if (existing != NULL) {
        return existing;
    }

    if (table->connection_count == TCP_MAX_CONNECTIONS) {
        return NULL;
    }

    TcpConnection *new_connection =
        &table->connections[table->connection_count++];

    memset(new_connection, 0, sizeof(*new_connection));

    new_connection->key = *key;
    new_connection->status = TCP_CONN_NEW;
    new_connection->handshake_state = TCP_HANDSHAKE_WAIT_SYN;

    return new_connection;
}

int tcp_flow_reverse_equal(
    const TcpFlowKey *first,
    const TcpFlowKey *second
) {
    if (first == NULL || second == NULL) {
        return 0;
    }

    return first->source_ip == second->destination_ip &&
           first->destination_ip == second->source_ip &&
           first->source_port == second->destination_port &&
           first->destination_port == second->source_port;
}

TcpConnection *tcp_connection_find_bidirectional(
    TcpConnectionTable *table,
    const TcpFlowKey *key
) {
    if (table == NULL || key == NULL ||
        table->connection_count > TCP_MAX_CONNECTIONS) {
        return NULL;
    }

    for (size_t i = 0; i < table->connection_count; i++) {
        TcpConnection *current = &table->connections[i];

        if (tcp_flow_equal(&current->key, key) ||
            tcp_flow_reverse_equal(&current->key, key)) {
            return current;
        }
    }

    return NULL;
}

TcpDirection tcp_connection_direction(
    const TcpConnection *connection,
    const TcpFlowKey *key
) {
    if (connection == NULL || key == NULL) {
        return TCP_DIRECTION_INVALID;
    }

    if (tcp_flow_equal(&connection->key, key)) {
        return TCP_DIRECTION_FORWARD;
    }

    if (tcp_flow_reverse_equal(&connection->key, key)) {
        return TCP_DIRECTION_REVERSE;
    }

    return TCP_DIRECTION_INVALID;
}

TcpDirectionState *tcp_connection_direction_state(
    TcpConnection *connection,
    const TcpFlowKey *key
) {
    TcpDirection direction =
        tcp_connection_direction(connection, key);

    if (direction == TCP_DIRECTION_FORWARD) {
        return &connection->forward;
    }

    if (direction == TCP_DIRECTION_REVERSE) {
        return &connection->reverse;
    }

    return NULL;
}

int tcp_connection_process_event(
    TcpConnection *connection,
    TcpConnectionEvent event
) {
    if (connection == NULL) {
        return 0;
    }

    if (connection->status == TCP_CONN_CLOSED) {
        return 0;
    }

    switch (event) {
        case TCP_EVENT_SYN:
            if (connection->handshake_state !=
                TCP_HANDSHAKE_WAIT_SYN) {
                return 0;
            }

            connection->handshake_state =
                TCP_HANDSHAKE_WAIT_SYN_ACK;
            return 1;

        case TCP_EVENT_SYN_ACK:
            if (connection->handshake_state !=
                TCP_HANDSHAKE_WAIT_SYN_ACK) {
                return 0;
            }

            connection->handshake_state =
                TCP_HANDSHAKE_WAIT_ACK;
            return 1;

        case TCP_EVENT_ACK:
            if (connection->handshake_state !=
                TCP_HANDSHAKE_WAIT_ACK) {
                return 0;
            }

            connection->handshake_state =
                TCP_HANDSHAKE_COMPLETE;

            connection->status = TCP_CONN_ESTABLISHED;
            return 1;

        case TCP_EVENT_FIN:
        case TCP_EVENT_RST:
            connection->status = TCP_CONN_CLOSED;
            return 1;

        default:
            return 0;
    }
}
