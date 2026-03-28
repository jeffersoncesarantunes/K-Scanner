CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -O2 -std=c99 -D_DEFAULT_SOURCE
OBJ_DIR = build/obj
DUMP_DIR = build/dumps
TARGET = bin/kscanner

SRCS = $(shell find src -name "*.c")
OBJS = $(SRCS:src/%.c=$(OBJ_DIR)/%.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "● Linking $(TARGET)..."
	@mkdir -p bin
	@mkdir -p $(DUMP_DIR)
	$(CC) $(OBJS) -o $(TARGET)
	@echo "✔ Build successful! Run with: sudo ./$(TARGET)"

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	@echo "  ○ Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

clean-dumps:
	@echo "🧹 Cleaning forensic dumps from $(DUMP_DIR)..."
	@rm -f $(DUMP_DIR)/*.bin
	@echo "✔ Dumps removed."

clean:
	@echo "🧹 Cleaning project artifacts..."
	@rm -rf build/
	@rm -rf bin/
	@echo "✔ Clean complete."

.PHONY: all clean clean-dumps
