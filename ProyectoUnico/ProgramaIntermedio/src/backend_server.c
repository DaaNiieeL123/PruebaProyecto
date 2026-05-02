#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DEFAULT_BACKEND_PORT 8090
#define DEFAULT_DAEMON_PORT 8091
#define MAX_REQ 65536
#define CHUNK_SIZE 8192

static volatile sig_atomic_t g_running = 1;
static int g_server_fd = -1;
static int g_backend_port = DEFAULT_BACKEND_PORT;
static int g_daemon_port = DEFAULT_DAEMON_PORT;
static char g_daemon_host[64] = "127.0.0.1";

static void usage(const char *prog) {
    fprintf(stderr,
            "Uso: %s [-p backend_port] [-h daemon_host] [-u daemon_port]\n"
            "  -p  Puerto del backend HTTP (default: %d)\n"
            "  -h  Host/IP del daemon interno (default: %s)\n"
            "  -u  Puerto del daemon interno (default: %d)\n",
            prog,
            DEFAULT_BACKEND_PORT,
            "127.0.0.1",
            DEFAULT_DAEMON_PORT);
}

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
}

static int send_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int starts_with_ci(const char *line, const char *prefix) {
    size_t i;
    for (i = 0; prefix[i]; i++) {
        char a = line[i];
        char b = prefix[i];
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b - 'A' + 'a');
        }
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

static ssize_t find_header_end(const char *buf, size_t len) {
    if (len < 4) {
        return -1;
    }
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return (ssize_t)i;
        }
    }
    return -1;
}

static size_t parse_content_length(const char *buf, size_t header_len) {
    const char *p = buf;
    const char *end = buf + header_len;

    while (p < end) {
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) {
            break;
        }

        size_t line_len = (size_t)(line_end - p);
        if (line_len > 0 && p[line_len - 1] == '\r') {
            line_len--;
        }

        if (line_len > 0 && starts_with_ci(p, "content-length:")) {
            const char *value = p + strlen("content-length:");
            while (value < p + line_len && (*value == ' ' || *value == '\t')) {
                value++;
            }
            return (size_t)strtoull(value, NULL, 10);
        }

        p = line_end + 1;
    }

    return 0;
}

static int connect_upstream(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_daemon_port);
    if (inet_pton(AF_INET, g_daemon_host, &addr.sin_addr) != 1) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static void send_bad_gateway(int client_fd, const char *msg) {
    char body[256];
    int body_len = snprintf(body,
                            sizeof(body),
                            "{\"error\":\"backend_proxy_error\",\"detail\":\"%s\"}",
                            msg ? msg : "backend no pudo conectar con daemon");
    if (body_len < 0) {
        return;
    }

    char resp[512];
    int n = snprintf(resp,
                     sizeof(resp),
                     "HTTP/1.1 502 Bad Gateway\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %d\r\n"
                     "Connection: close\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "\r\n"
                     "%s",
                     body_len,
                     body);
    if (n > 0) {
        (void)send_all(client_fd, resp, (size_t)n);
    }
}

static int proxy_request(int client_fd, const char *request, size_t request_len) {
    int upstream = connect_upstream();
    if (upstream < 0) {
        return -1;
    }

    if (send_all(upstream, request, request_len) < 0) {
        close(upstream);
        return -1;
    }

    char chunk[CHUNK_SIZE];
    int bytes_from_upstream = 0;
    while (1) {
        ssize_t n = recv(upstream, chunk, sizeof(chunk), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(upstream);
            return -1;
        }
        if (n == 0) {
            break;
        }
        bytes_from_upstream += (int)n;
        if (send_all(client_fd, chunk, (size_t)n) < 0) {
            close(upstream);
            return -1;
        }
    }

    close(upstream);
    if (bytes_from_upstream == 0) {
        return -1;
    }
    return 0;
}

static void handle_client(int client_fd) {
    char req[MAX_REQ + 1];
    size_t used = 0;
    ssize_t header_end = -1;
    size_t content_len = 0;

    while (used < MAX_REQ) {
        ssize_t n = recv(client_fd, req + used, MAX_REQ - used, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(client_fd);
            return;
        }
        if (n == 0) {
            break;
        }

        used += (size_t)n;
        req[used] = '\0';

        if (header_end < 0) {
            header_end = find_header_end(req, used);
            if (header_end >= 0) {
                content_len = parse_content_length(req, (size_t)header_end + 4);
            }
        }

        if (header_end >= 0) {
            size_t total_needed = (size_t)header_end + 4 + content_len;
            if (used >= total_needed) {
                break;
            }
        }
    }

    if (used == 0 || header_end < 0) {
        close(client_fd);
        return;
    }

    if (proxy_request(client_fd, req, used) < 0) {
        send_bad_gateway(client_fd, "daemon no disponible");
    }

    close(client_fd);
}

static int start_server(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 64) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "p:h:u:")) != -1) {
        switch (opt) {
        case 'p':
            g_backend_port = atoi(optarg);
            break;
        case 'h':
            strncpy(g_daemon_host, optarg, sizeof(g_daemon_host) - 1);
            g_daemon_host[sizeof(g_daemon_host) - 1] = '\0';
            break;
        case 'u':
            g_daemon_port = atoi(optarg);
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (g_backend_port <= 0 || g_daemon_port <= 0) {
        usage(argv[0]);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    g_server_fd = start_server(g_backend_port);
    if (g_server_fd < 0) {
        perror("start_server");
        return 1;
    }

    printf("[backend] escuchando en 0.0.0.0:%d -> daemon %s:%d\n",
           g_backend_port,
           g_daemon_host,
           g_daemon_port);

    while (g_running) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int cfd = accept(g_server_fd, (struct sockaddr *)&caddr, &clen);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (g_running) {
                perror("accept");
            }
            break;
        }

        handle_client(cfd);
    }

    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }

    return 0;
}
