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

int8_t f_read(int8_t vfd, void *buf, uint8_t count)
{
	if (count == 0)
		return 0;

	// Send READ command
	outb(FILE_PORT, CMD_READ);

	// Send vfd
	outb(FILE_PORT, (uint8_t)vfd);

	// Send count
	outb(FILE_PORT, count);

	// Get the number of bytes read
	int8_t bytes_read = (int8_t)inb(FILE_PORT);

	if (bytes_read <= 0)
	{
		return bytes_read; // Return 0 EOF or -1 error
	}

	// Read that many bytes into the buffer
	uint8_t *p = (uint8_t *)buf;
	for (int i = 0; i < bytes_read; i++)
	{
		p[i] = inb(FILE_PORT);
	}

	return bytes_read;
}

int8_t f_write(int8_t vfd, const void *buf, uint8_t count)
{
	if (count == 0)
		return 0;

	// Send WRITE command
	outb(FILE_PORT, CMD_WRITE);

	// Send vfd
	outb(FILE_PORT, (uint8_t)vfd);

	// Send count
	outb(FILE_PORT, count);

	// Send all the data bytes
	const uint8_t *p = (const uint8_t *)buf;
	for (int i = 0; i < count; i++)
	{
		outb(FILE_PORT, p[i]);
	}

	// Get the result (bytes written or -1)
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


	puts("Guest: Booted. Starting file tests...\n");

	// --- Test 1: Open a shared file for reading ---
	puts("Guest: 1. Opening 'new_file.txt' (O_WRITE)... ");
	int8_t fd = f_open("new_file.txt", O_WRITE);

	if (fd < 0)
	{
		puts("FAILED.\n");
	}
	else
	{
		puts("SUCCESS. (vfd=");
		outb(SERIAL_PORT, '0' + fd);
		puts(")\n");

		// --- NEW: Write to the file ---
		const char *msg = "Hello from the VM!";
		int msg_len = 18;
		puts("Guest: 1b. Writing 'Hello from the VM!'...\n");
		int8_t bytes_written = f_write(fd, msg, msg_len);

		if (bytes_written == msg_len)
		{
			puts("Guest: Write SUCCESS.\n");
		}
		else
		{
			puts("Guest: Write FAILED.\n");
		}

		puts("Guest: 1c. Closing file...");
		f_close(fd);
		puts("DONE.\n");
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
