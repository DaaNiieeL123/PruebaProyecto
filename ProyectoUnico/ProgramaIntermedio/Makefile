CC := gcc
CFLAGS := -O2 -Wall -Wextra -pthread
LDFLAGS := -pthread -lpam -lpam_misc

DAEMON_SRC := src/security_daemon.c
DAEMON_BIN := security_daemon
BACKEND_SRC := src/backend_server.c
BACKEND_BIN := backend_server

all: $(DAEMON_BIN) $(BACKEND_BIN)


$(DAEMON_BIN): $(DAEMON_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BACKEND_BIN): $(BACKEND_SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(DAEMON_BIN) $(BACKEND_BIN)

run: all
	bash scripts/run_live.sh

stop:
	pkill -f "$(CURDIR)/backend_server" || true
	pkill -f "$(CURDIR)/security_daemon" || true

status:
	@pgrep -af "$(CURDIR)/security_daemon|$(CURDIR)/backend_server" || echo "No hay procesos activos"

.PHONY: all clean run stop status
