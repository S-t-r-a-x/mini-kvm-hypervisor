#include <stdint.h>

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

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {

	/*
		INSERT CODE BELOW THIS LINE
	*/
	
	const char *p;
	uint16_t port = 0xE9;

	for (p = "Cao, svete!\n"; *p; ++p)
		outb(port, *p);

	/*
		INSERT CODE ABOVE THIS LINE
	*/

	for (;;)
		asm("hlt");
}
