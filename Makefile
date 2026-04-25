CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -O2 -std=c99 -D_DEFAULT_SOURCE
LDFLAGS = -lncurses
OBJ_DIR = build/obj
DUMP_DIR = build/dumps
TARGET = kscanner

SRCS = $(shell find src -name "*.c")
OBJS = $(SRCS:src/%.c=$(OBJ_DIR)/%.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(DUMP_DIR)
	@$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo "✔ Build successful! 🟢"

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

triage:
	@chmod +x scripts/forensic_triage.sh
	@./scripts/forensic_triage.sh $(PID)

clean-dumps:
	@echo "🧹 Cleaning forensic dumps..."
	@rm -f $(DUMP_DIR)/*.bin
	@echo "✔ Dumps removed. 🟢"

clean:
	@echo "🧹 Cleaning project artifacts..."
	@rm -rf build/
	@rm -f $(TARGET)
	@echo "✔ Clean complete. 🟢"

.PHONY: all clean clean-dumps triage
