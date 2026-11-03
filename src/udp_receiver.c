#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (socket_fd == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(9000);

    if (inet_pton(AF_INET, "10.0.2.2", &server_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address\n");
        close(socket_fd);
        return 1;
    }

    if (bind(
        socket_fd,
        (struct sockaddr *)&server_addr,
        sizeof(server_addr)
    ) == -1) {
        perror("bind");
        close(socket_fd);
        return 1;
    }

    char data[2048];

    printf("UDP receiver is ready...\n");
    fflush(stdout);

    ssize_t bytes = recvfrom(
        socket_fd,
        data,
        sizeof(data) - 1,
        0,
        NULL,
        NULL
    );

    if (bytes == -1) {
        perror("recvfrom");
        close(socket_fd);
        return 1;
    }

    data[bytes] = '\0';

    printf("Message received: %s\n", data);

    close(socket_fd);

    return 0;
}
