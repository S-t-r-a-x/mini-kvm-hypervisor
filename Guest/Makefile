GUESTS = guest.img guest2.img

all: $(GUESTS)

%.img: %.o
	ld -T guest.ld $< -o $@

%.o: %.c
	$(CC) -m64 -ffreestanding -fno-pic -c -o $@ $^

clean:
	rm -f *.o $(GUESTS)

.PHONY: all clean