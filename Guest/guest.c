#include <stdint.h>


// port for file related commands
#define FILE_PORT 0x0278
#define MAX_PATH_LENGTH 254
// file command encode
#define CMD_OPEN 0x01
#define CMD_CLOSE 0x02
#define CMD_READ 0x03
#define CMD_WRITE 0x04

// flags for file open
#define O_READ 0x00
#define O_WRITE 0x01

#define SERIAL_PORT 0xE9

// out %al, (%dx)
static void outb(uint16_t port, uint8_t value) {
		asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

// in (%dx), %al
static uint8_t inb(uint16_t port) {
	uint8_t result;
	asm("inb %1, %0" : "=a" (result) : "Nd" (port) : "memory");
	return result;
}

static void puts(const char *s)
{
	while (*s)
	{
		outb(SERIAL_PORT, *s++);
	}
}

static uint8_t f_open(char* file_path, uint8_t flags){

	// initialize file open
	outb(FILE_PORT, CMD_OPEN);

	// send flags for fopen
	outb(FILE_PORT, flags);

	int len = 0;
	// if 255 is sent, path length is too long
	while (file_path[len] && len < MAX_PATH_LENGTH + 1)
	{
		len++;
	}
	// send path length
	outb(FILE_PORT, len);

	// send path
	for(int i = 0; i < len; i++) {
		outb(FILE_PORT, (uint8_t)file_path[i]);
	}

	// get virtual file descriptor
	return (int8_t)inb(FILE_PORT);
}

static int8_t f_close(int8_t vfd)
{
	// end the close command
	outb(FILE_PORT, CMD_CLOSE);

	// send the virtual FD
	outb(FILE_PORT, (uint8_t)vfd);

	// get the result (0 or -1)
	return (int8_t)inb(FILE_PORT);
}


void
	__attribute__((noreturn))
	__attribute__((section(".start")))
	_start(void)
{

	/*
		INSERT CODE BELOW THIS LINE
	*/

	puts("Guest: Booted. Starting file tests...\n");

	// --- Test 1: Open a new file for writing ---
	puts("Guest: 1. Opening 'new_file.txt' (O_WRITE)... ");
	int8_t fd1 = f_open("new_file.txt", O_WRITE);

	if (fd1 < 0)
	{
		puts("FAILED.\n");
	}
	else
	{
		puts("SUCCESS. (vfd=");
		outb(SERIAL_PORT, '0' + fd1);
		puts(")\n");

		// --- NEW: Close the file ---
		puts("Guest: 1b. Closing 'new_file.txt'...");
		if (f_close(fd1) == 0)
		{
			puts("SUCCESS.\n");
		}
		else
		{
			puts("FAILED.\n");
		}
	}

	// --- Test 2: Open a shared file for reading ---
	// (Requires hypervisor to be run with '-f shared.txt')
	puts("Guest: 2. Opening 'shared.txt' (O_READ)... ");
	int8_t fd2 = f_open("shared.txt", O_READ);

	if (fd2 < 0)
	{
		puts("FAILED.\n");
	}
	else
	{
		puts("SUCCESS. (vfd=");
		outb(SERIAL_PORT, '0' + fd2);
		puts(")\n");
	}
	/*
		INSERT CODE ABOVE THIS LINE
	*/

	for (;;)
		asm("hlt");
}
