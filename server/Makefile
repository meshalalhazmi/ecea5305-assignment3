# Compiler (can be overridden from command line)
CC := $(CROSS_COMPILE)gcc

# Compiler flags
CFLAGS := -g -Wall -Werror -O0

# Target executable
TARGET := aesdsocket

# Default target
all: $(TARGET)

# Link step
$(TARGET): aesdsocket.o
	$(CC) $(CFLAGS) aesdsocket.o -o $(TARGET)

# Compile step
aesdsocket.o: aesdsocket.c
	$(CC) $(CFLAGS) -c aesdsocket.c -o aesdsocket.o
# Clean target
clean:
	rm -f *.o $(TARGET) *.elf *.map


#usage make CROSS_COMPILE=aarch64-none-linux-gnu- all
#usage make CROSS_COMPILE=aarch64-none-linux-gnu- clean