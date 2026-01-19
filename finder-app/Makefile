# Compiler (can be overridden from command line)
CC := $(CROSS_COMPILE)gcc

# Compiler flags
CFLAGS := -g -Wall -Werror

# Target executable
TARGET := writer

# Default target
all: $(TARGET)

# Link step
$(TARGET): writer.o
	$(CC) $(CFLAGS) writer.o -o $(TARGET)

# Compile step
writer.o: writer.c
	$(CC) $(CFLAGS) -c writer.c -o writer.o

# Clean target
clean:
	rm -f *.o $(TARGET) *.elf *.map


#usage make CROSS_COMPILE=aarch64-none-linux-gnu- all
#usage make CROSS_COMPILE=aarch64-none-linux-gnu- clean