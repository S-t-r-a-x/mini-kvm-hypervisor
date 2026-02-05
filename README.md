# Mini KVM Hypervisor

A minimal Type-2 hypervisor implementation using the Linux Kernel-based Virtual Machine (KVM) API.

## Overview

The project implements a hypervisor in C that runs bare-metal guest programs in 64-bit long mode. It is divided into three incremental versions (A, B, C), each adding new functionality.

## Project Structure

```
├── Version_A/          # Basic hypervisor (single VM)
│   ├── mini_hypervisor.c
│   └── Makefile
├── Version_B/          # Multi-VM support (POSIX threads)
│   ├── mini_hypervisor.c
│   └── Makefile
├── Version_C/          # Full implementation with file I/O
│   ├── mini_hypervisor.c
│   └── Makefile
├── Guest/              # Guest source, linker script, Makefile
│   ├── guest.c
│   ├── guest2.c
│   ├── guest.ld
│   └── Makefile
└── README.md
```

## Requirements

- **Linux** with KVM support (Intel VT-x or AMD-V)
- **GCC** (or compatible C compiler)
- **Make**
- **Root/sudo** access to run the hypervisor (KVM requires `/dev/kvm`)

### Verifying KVM Support

```bash
# Check if KVM is available
ls -l /dev/kvm

# Verify hardware virtualization (Intel)
grep -E '(vmx|svm)' /proc/cpuinfo
```

Ensure your user is in the `kvm` group, or run with `sudo`:

```bash
# Add user to kvm group (one-time setup)
sudo usermod -aG kvm $USER
# Log out and back in for changes to take effect
```

## Building

### Build Guest Images

From the project root:

```bash
cd Guest
make
```

This produces `guest.img` and `guest2.img` — flat binary executables that run at physical address 0 in 64-bit long mode.

### Build the Hypervisor

Each version has its own directory. Build from the appropriate folder:

```bash
# Version A (single VM)
cd Version_A && make

# Version B (multi-VM, requires pthread)
cd Version_B && make
# If linking fails with pthread errors: gcc -lpthread mini_hypervisor.c -o mini_hypervisor

# Version C (multi-VM + file I/O)
cd Version_C && make
```

## Versions

| | Version A | Version B | Version C |
|---|:---:|:---:|:---:|
| **Scope** | Single VM | Multi-VM (threads) | Multi-VM + file I/O |
| **Serial I/O** (port 0xE9) | ✓ | ✓ | ✓ |
| **File I/O** (port 0x0278) | — | — | ✓ |
| **Shared files** (`-f`) | — | — | ✓ |

---

## Running the Hypervisor

Run `mini_hypervisor` from its version directory (`Version_A/`, `Version_B/`, or `Version_C/`). All paths (guest images, shared files) are relative to the current working directory.

### Version A

**Invocation:**
```
./mini_hypervisor -m <2|4|8> -p <4|2> -g <guest.img>
./mini_hypervisor --memory <2|4|8> --page <4|2> --guest <guest.img>
```

**Required arguments:**
- `-m`, `--memory` — Guest RAM size in MB: **2**, **4**, or **8**
- `-p`, `--page` — Page size: **4** (4 KB) or **2** (2 MB)
- `-g`, `--guest` — Path to the guest binary (flat image)

**Example** (from `Version_A/`):
```bash
./mini_hypervisor -m 4 -p 2 -g ../Guest/guest2.img
```

### Version B

**Invocation:**
```
./mini_hypervisor -m <2|4|8> -p <4|2> -g <guest1.img> [guest2.img] [guest3.img] ...
```

Same options as Version A. The `-g` option accepts one or more guest images; each image is run in a separate VM (POSIX thread).

**Example** (from `Version_B/`):
```bash
./mini_hypervisor -m 4 -p 2 -g ../Guest/guest2.img ../Guest/guest2.img
```

### Version C

**Invocation:**
```
./mini_hypervisor -m <2|4|8> -p <4|2> -g <guest1.img> [guest2.img] ... [-f <file1> [file2] ...]
```

Same as Version B, plus:
- `-f`, `--file` — Path(s) to files shared with all VMs. Optional.

**Shared files** — Files passed via `-f` are visible to every guest. Initially they are read-only: all VMs see the same host file. If a guest opens a shared file for write and writes to it, the hypervisor creates a private copy for that VM (copy-on-write); subsequent reads and writes by that VM use its copy, and other VMs are unaffected. A guest can also create new files (open for write creates the file if it does not exist); those files are private to that VM. A guest may only access files it created or shared files it has been given read access to.

**Example** (from `Version_C/`):
```bash
echo "Hello from host" > ../Guest/shared.txt
./mini_hypervisor -m 4 -p 2 -g ../Guest/guest.img -f ../Guest/shared.txt
```

---

## Writing a Guest

Guests are bare-metal 64-bit programs with no libc. Build with:

```bash
gcc -m64 -ffreestanding -fno-pic -c guest.c -o guest.o
ld -T guest.ld guest.o -o guest.img
```

Use the provided `guest.ld` linker script so the `.start` section is at the beginning. Entry point:

```c
void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {
    // your code
    for (;;) asm("hlt");  // required: guest must halt
}
```

### Guest Runtime

All versions: 64-bit long mode, identity-mapped memory (2/4/8 MB), one vCPU. The guest must terminate with `hlt` in an infinite loop. Capabilities by version are summarized in the table above.

**Version A** — Single VM. Serial I/O only.

**Version B** — Multiple VMs run concurrently; each is isolated. Serial I/O is mutex-protected across VMs.

**Version C** — Same as B, plus file I/O. See the Version C running section for shared-file behavior.

### Serial I/O (port 0xE9)

One byte at a time:

```c
#define SERIAL_PORT 0xE9
static void outb(uint16_t port, uint8_t value) {
    asm("outb %0,%1" : : "a"(value), "Nd"(port) : "memory");
}
static uint8_t inb(uint16_t port) {
    uint8_t result;
    asm("inb %1,%0" : "=a"(result) : "Nd"(port) : "memory");
    return result;
}
```

### File I/O (port 0x0278)

Port `0x0278` uses a command protocol (CMD_OPEN, CMD_CLOSE, CMD_READ, CMD_WRITE). See `Guest/guest2.c` for example implementations of `f_open`, `f_close`, `f_read`, and `f_write` that you can copy into your guest.

## Technical Details

### Memory Layout

- Identity mapping: virtual address = physical address; execution starts at 0
- 4-level paging (PML4 → PDPT → PD → PT) for 4 KB pages
- 2 MB large pages when page size is 2 MB

### I/O Ports

| Port    | Purpose                              |
|---------|--------------------------------------|
| `0xE9`  | Serial I/O (1 byte in/out)           |
| `0x0278`| File hypercalls (Version C only)     |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `open /dev/kvm: Permission denied` | Add user to `kvm` group or run with `sudo` |
| `KVM not supported` | Enable VT-x/AMD-V in BIOS; ensure no nested virtualization conflict |
| Version B: undefined reference to `pthread_*` | Add `-lpthread`: `gcc -lpthread mini_hypervisor.c -o mini_hypervisor` |
| Version C: file not found | Shared file paths are relative to the current working directory; run from `Version_C/` and use `../Guest/shared.txt` |
| Guest image too large | Ensure guest binary fits in allocated memory (2/4/8 MB) |

## License

This project was developed for educational purposes. Use and modification are at your discretion.

---

*Originally developed for the Architecture and Organization of Computers 2 course at the University of Belgrade, School of Electrical Engineering.*
