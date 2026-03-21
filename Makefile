CC = gcc
# Flags de otimização e segurança
CFLAGS = -Wall -Wextra -Iinclude -O2 -std=c99 -D_DEFAULT_SOURCE
OBJ_DIR = build/obj
TARGET = build/kscanner

# Localiza todos os .c em src/ e subpastas
SRCS = $(shell find src -name "*.c")
# Mapeia os objetos mantendo a hierarquia de pastas em build/obj
OBJS = $(SRCS:src/%.c=$(OBJ_DIR)/%.o)

all: $(TARGET)

# A regra do TARGET agora depende da criação dos diretórios
$(TARGET): $(OBJS)
	@echo "● Linking $(TARGET)..."
	@mkdir -p $(@D)
	$(CC) $(OBJS) -o $(TARGET)
	@echo "✔ Build successful! Run with: sudo ./$(TARGET)"

# Regra de compilação com criação automática de subpastas
$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	@echo "  ○ Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "🧹 Cleaning project artifacts..."
	@rm -rf build/
	@if [ -d "dumps" ]; then rm -rf dumps/ && echo "● Forensic dumps removed."; fi
	@echo "✔ Clean complete."

.PHONY: all clean
