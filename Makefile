CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -Iinclude -O2 -std=c99 -D_DEFAULT_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS = -lncurses -Wl,-z,relro,-z,now
OBJ_DIR = build/obj
BPF_DIR = build/bpf
DUMP_DIR = build/dumps
TARGET = kscanner

CLANG ?= clang
BPF_CFLAGS = -target bpf -g -O2
BPF_OBJ = $(BPF_DIR)/rwx_monitor.bpf.o

SRCS = $(shell find src -name "*.c" ! -path "src/bpf/*")
OBJS = $(SRCS:src/%.c=$(OBJ_DIR)/%.o)

HAVE_LIBBPF := $(shell pkg-config --exists libbpf 2>/dev/null && echo 1 || echo 0)

ifeq ($(HAVE_LIBBPF),1)
CFLAGS += -DHAVE_LIBBPF
LDFLAGS += $(shell pkg-config --libs libbpf)
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(DUMP_DIR) $(BPF_DIR)
	@$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@strip $(TARGET)
	@echo "OK Build successful!"

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

bpf: $(BPF_DIR) $(BPF_OBJ)

$(BPF_DIR):
	@mkdir -p $(BPF_DIR)

$(BPF_OBJ): src/bpf/rwx_monitor.bpf.c | $(BPF_DIR)
	@echo "  BPF  $<"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@

PREFIX ?= /usr/local
BINDIR  = $(PREFIX)/bin
SHAREDIR = $(PREFIX)/share/kscanner

install: $(TARGET) bpf
	@mkdir -p $(BINDIR) $(SHAREDIR)
	@install -m 755 $(TARGET) $(BINDIR)/$(TARGET)
	@install -m 644 $(BPF_OBJ) $(SHAREDIR)/rwx_monitor.bpf.o
	@sha256sum $(SHAREDIR)/rwx_monitor.bpf.o > $(SHAREDIR)/rwx_monitor.bpf.o.sha256
	@echo "  Installed $(TARGET) to $(BINDIR)"
	@echo "  Installed BPF object to $(SHAREDIR)"

uninstall:
	@rm -f $(BINDIR)/$(TARGET)
	@rm -f $(SHAREDIR)/rwx_monitor.bpf.o
	@-rmdir $(SHAREDIR) 2>/dev/null; true
	@echo "  Removed $(TARGET)"

test: $(TARGET) bpf
	@echo ""
	@echo "--- Test 1: Help output ---"
	@./$(TARGET) --help > /tmp/kscanner_test.txt 2>&1
	@grep -q "Usage:" /tmp/kscanner_test.txt && echo "  PASS" || echo "  FAIL"
	@echo ""
	@echo "--- Test 2: JSON export (headless) ---"
	@./$(TARGET) --json > /tmp/kscanner_json.txt 2>&1
	@grep -q '^\[' /tmp/kscanner_json.txt && echo "  PASS" || echo "  FAIL"
	@echo ""
	@echo "--- Test 3: CSV export (headless) ---"
	@./$(TARGET) --csv > /tmp/kscanner_csv.txt 2>&1
	@grep -q "PID,PROCESS" /tmp/kscanner_csv.txt && echo "  PASS" || echo "  FAIL"
	@echo ""
	@echo "--- Test 4: BPF object integrity ---"
	@test -f $(BPF_OBJ) && readelf -S $(BPF_OBJ) >/dev/null 2>&1 && echo "  PASS" || echo "  FAIL"
	@echo ""

debug:
	@$(MAKE) CFLAGS="-Wall -Wextra -Wpedantic -Iinclude -O0 -g -std=c99 -D_DEFAULT_SOURCE -DDEBUG" clean $(TARGET)

triage:
	@chmod +x scripts/forensic_triage.sh 2>/dev/null; true
	@./scripts/forensic_triage.sh $(PID)

clean-dumps:
	@rm -f $(DUMP_DIR)/*.bin $(DUMP_DIR)/*.sha256 $(DUMP_DIR)/*.strings.txt $(DUMP_DIR)/*.hex.txt
	@echo "Dumps cleaned."

clean:
	@echo "Clean."
	@rm -rf build/
	@rm -f $(TARGET)

.PHONY: all bpf install uninstall test debug triage clean-dumps clean
