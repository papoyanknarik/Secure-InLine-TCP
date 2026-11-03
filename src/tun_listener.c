#include "tun_device.h"

#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 2) {
        fprintf(stderr, "Usage: %s <tun-interface>\n", argv[0]);
        return 1;
    }

    const char *interface_name = argv[1];

    int tun_fd = tun_open(interface_name);

    if (tun_fd == -1) {
        perror("Failed to open TUN device");
        return 1;
    }

    printf("Interface %s is ready\n", interface_name);
    printf("Listening for incoming packets...\n");
    fflush(stdout);

    unsigned char buffer[65535];

    for (;;) {
        ssize_t packet_size = tun_read_packet(
            tun_fd,
            buffer,
            sizeof(buffer)
        );

        if (packet_size == -1) {
            perror("TUN packet reading failed");
            close(tun_fd);
            return 1;
        }

        printf("IP packet captured: %zd bytes\n", packet_size);
        fflush(stdout);
    }

    close(tun_fd);
    return 0;
}
