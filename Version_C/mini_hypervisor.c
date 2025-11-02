#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <getopt.h>
#include <stdbool.h>
#include <pthread.h>


#define GUEST_START_ADDR 0x0000 // Početna adresa za učitavanje gosta
#define MAX_GUESTS 32 // max number of vm guests 
#define MAX_SHARED_FILES 32 // max number of files that can be passed via the command line

// PDE bitovi
#define PDE64_PRESENT (1u << 0)
#define PDE64_RW (1u << 1)
#define PDE64_USER (1u << 2)
#define PDE64_PS (1u << 7)

// CR4 i CR0
#define CR0_PE (1u << 0)
#define CR0_PG (1u << 31)
#define CR4_PAE (1u << 5)

#define EFER_LME (1u << 8)
#define EFER_LMA (1u << 10)

struct vm {
	int kvm_fd;
	int vm_fd;
	int vcpu_fd;
	char *mem;
	size_t mem_size;
	struct kvm_run *run;
	int run_mmap_size;
};

int vm_init(struct vm *v, size_t mem_size)
{
	struct kvm_userspace_memory_region region;	

	memset(v, 0, sizeof(*v));
	v->kvm_fd = v->vm_fd = v->vcpu_fd = -1;
	v->mem = MAP_FAILED;
	v->run = MAP_FAILED;
	v->run_mmap_size = 0;
	v->mem_size = mem_size;

	v->kvm_fd = open("/dev/kvm", O_RDWR);
	if (v->kvm_fd < 0) {
		perror("open /dev/kvm");
		return -1;
	}

    int api = ioctl(v->kvm_fd, KVM_GET_API_VERSION, 0);
    if (api != KVM_API_VERSION) {
        printf("KVM API mismatch: kernel=%d headers=%d\n", api, KVM_API_VERSION);
        return -1;
    }

	v->vm_fd = ioctl(v->kvm_fd, KVM_CREATE_VM, 0);
	if (v->vm_fd < 0) {
		perror("KVM_CREATE_VM");
		return -1;
	}

	v->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (v->mem == MAP_FAILED) {
		perror("mmap mem");
		return -1;
	}

	region.slot = 0;
	region.flags = 0;
	region.guest_phys_addr = 0;
	region.memory_size = v->mem_size;
	region.userspace_addr = (uintptr_t)v->mem;
    if (ioctl(v->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
	}

	v->vcpu_fd = ioctl(v->vm_fd, KVM_CREATE_VCPU, 0);
    if (v->vcpu_fd < 0) {
		perror("KVM_CREATE_VCPU");
        return -1;
	}

	v->run_mmap_size = ioctl(v->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (v->run_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
		return -1;
	}

	v->run = mmap(NULL, v->run_mmap_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, v->vcpu_fd, 0);
	if (v->run == MAP_FAILED) {
		perror("mmap kvm_run");
		return -1;
	}

	return 0;
}

void vm_destroy(struct vm *v) {
	if (v->run && v->run != MAP_FAILED) {
		munmap(v->run, (size_t)v->run_mmap_size);
		v->run = MAP_FAILED;
	}

	if(v->mem && v->mem != MAP_FAILED) {
		munmap(v->mem, v->mem_size);
		v->mem = MAP_FAILED;
	}

	if (v->vcpu_fd >= 0) {
		close(v->vcpu_fd);
		v->vcpu_fd = -1;
	}

	if (v->vm_fd >= 0) {
		close(v->vm_fd);
		v->vm_fd = -1;
	}

	if (v->kvm_fd >= 0) {
		close(v->kvm_fd);
		v->kvm_fd = -1;
	}
}

static void setup_segments_64(struct kvm_sregs *sregs)
{
	// .selector = 0x8,
	struct kvm_segment code = {
		.base = 0,
		.limit = 0xffffffff,
		.present = 1, // Prisutan ili učitan u memoriji
		.type = 11, // Code: execute, read, accessed
		.dpl = 0, // Descriptor Privilage Level: 0 (0, 1, 2, 3)
		.db = 0, // Default size - ima vrednost 0 u long modu
		.s = 1, // Code/data tip segmenta
		.l = 1, // Long mode - 1
		.g = 1, // 4KB granularnost
		.selector = 0x8,
	};
	struct kvm_segment data = code;
	data.type = 3; // Data: read, write, accessed
	data.l = 0;
	data.selector = 0x10; // Data segment selector

	sregs->cs = code;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = data;
}

// Omogucavanje long moda.
// Vise od long modu mozete prociati o stranicenju u glavi 5:
// https://docs.amd.com/v/u/en-US/24593_3.43
// Pogledati figuru 5.1 na stranici 128.
static void setup_long_mode(struct vm *v, struct kvm_sregs *sregs, bool is4KB)
{
	// Postavljanje 4 niva ugnjezdavanja.
	// Svaka tabela stranica ima 512 ulaza, a svaki ulaz je veličine 8B.
    // Odatle sledi da je veličina tabela stranica 4KB. Ove tabele moraju da budu poravnate na 4KB. 
	uint64_t page = 0;
	uint64_t pml4_addr = 0x11000; // Adrese su proizvoljne.
	uint64_t *pml4 = (void *)(v->mem + pml4_addr);

	uint64_t pdpt_addr = 0x12000;
	uint64_t *pdpt = (void *)(v->mem + pdpt_addr);

	uint64_t pd_addr = 0x13000;
	uint64_t *pd = (void *)(v->mem + pd_addr);
	
	memset((void *)pml4, 0, 0x1000);
    memset((void *)pdpt, 0, 0x1000);
    memset((void *)pd, 0, 0x1000);
	
	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
	
	
	if(is4KB) {
		// 4KB page size
		// -----------------------------------------------------
        uint64_t pt_base_addr = 0x14000;
        
        // Calculate how many 2MB blocks we have (e.g., 8MB / 2MB = 4)
        // Each 2MB block needs one Page Directory Entry (PDE) pointing to a Table (PT)
        size_t num_pd_entries = v->mem_size >> 21; // 512 entries  Page* 4KB = 2MB

        for (size_t i_pd = 0; i_pd < num_pd_entries; i_pd++) {
            // Each PD entry points to a new Page Table
            uint64_t pt_addr = pt_base_addr + (i_pd * 0x1000); // 4KB per table
            uint64_t *pt = (void *)(v->mem + pt_addr);
            memset((void *)pt, 0, 0x1000); /* clear PT page */

            // Set the PD entry to point to this PT
            pd[i_pd] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;

            // Fill all 512 entries of this Page Table
            for (size_t i_pt = 0; i_pt < 512; i_pt++) {
                // This formula calculates the identity-mapped physical address for each entry
                uint64_t phys_addr = (i_pd * 512 * 4096) + (i_pt * 4096);
                pt[i_pt] = phys_addr | PDE64_PRESENT | PDE64_RW | PDE64_USER;
            }
        }
	}
	else {
		// 2MB page size
		long num_pd_entries = v->mem_size >> 21;
		for(int i = 0; i < num_pd_entries; i++) {
			pd[i] = (i*0x200000ULL) | PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
		}
	}
	// -----------------------------------------------------

    // Registar koji ukazuje na PML4 tabelu stranica. Odavde kreće mapiranje VA u PA.
	sregs->cr3  = pml4_addr; 
	sregs->cr4  = CR4_PAE; // "Physical Address Extension" mora biti 1 za long mode.
	sregs->cr0  = CR0_PE | CR0_PG; // Postavljanje "Protected Mode" i "Paging" 
	sregs->efer = EFER_LME | EFER_LMA; // Postavljanje  "Long Mode Active" i "Long Mode Enable"

	// Inicijalizacija segmenata za 64-bitni mod rada.
	setup_segments_64(sregs);
}

int load_guest_image(struct vm *v, const char *image_path, uint64_t load_addr) {
	FILE *f = fopen(image_path, "rb");
	if (!f) {
		perror("Failed to open guest image");
		return -1;
	}

	if (fseek(f, 0, SEEK_END) < 0) {
		perror("Failed to seek to end of guest image");
		fclose(f);
		return -1;
	}

	long fsz = ftell(f);
	if (fsz < 0) {
		perror("Failed to get size of guest image");
		fclose(f);
		return -1;
	}
	rewind(f);

	if((uint64_t)fsz > v->mem_size - load_addr) {
		printf("Guest image is too large for the VM memory\n");
		fclose(f);
		return -1;
	}

	if (fread((uint8_t*)v->mem + load_addr, 1, (size_t)fsz, f) != (size_t)fsz) {
		perror("Failed to read guest image");
		fclose(f);
		return -1;
	}
	fclose(f);

	return 0;
}

// for passing params
struct InitVMData {
	size_t mem_size;
	long page_size;
	char *guest_path;
	int file_count;
	char **shared_files;
};


pthread_mutex_t io_mutex;

// VM THREAD DEFINITION
void *run_vm(void *data) {
	struct vm v;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	int stop = 0;
	int ret = 0;
	FILE* img;
	struct InitVMData *init_data = (struct InitVMData *)data;

	size_t mem_size = init_data->mem_size;
	long page_size = init_data->page_size;
	char *guest_path = init_data->guest_path;
	int file_count = init_data->file_count;
	char **shared_files = init_data->shared_files;

	if (vm_init(&v, mem_size)) {
		printf("Failed to init the VM\n");
		return NULL;
	}

	if (ioctl(v.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		vm_destroy(&v);
		return NULL;
	}

	setup_long_mode(&v, &sregs, page_size == 4);

    if (ioctl(v.vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		vm_destroy(&v);
		return NULL;
	}

	if (load_guest_image(&v, guest_path, GUEST_START_ADDR) < 0) {
		printf("Failed to load guest image\n");
		vm_destroy(&v);
		return NULL;
	}


	memset(&regs, 0, sizeof(regs));
	regs.rflags = 0x2;
	
	// PC se preko pt[0] ulaza mapira na fizičku adresu GUEST_START_ADDR (0x8000).
	// a na GUEST_START_ADDR je učitan gost program.
	regs.rip = 0; 
	regs.rsp = mem_size; // SP raste nadole

 
	if (ioctl(v.vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		return NULL;
	}

	while(stop == 0) {
		ret = ioctl(v.vcpu_fd, KVM_RUN, 0);
		if (ret == -1) {
			printf("KVM_RUN failed\n");
			vm_destroy(&v);
			return NULL;
		}

		switch (v.run->exit_reason) {
			case KVM_EXIT_IO:
				pthread_mutex_lock(&io_mutex);
				if(v.run -> io.port == 0xE9) {
					// Regular in/out operation
					if (v.run->io.direction == KVM_EXIT_IO_OUT) {
						char *p = (char *) v.run;
						printf("%c", *(p +v.run->io.data_offset));
						fflush(stdout);
					}
					else if (v.run->io.direction == KVM_EXIT_IO_IN) {
						int data;
						printf("Enter a value to send to the VM:\n");
						fflush(stdout);
						scanf("%d", &data);
						char *data_in = (((char *)v.run) + v.run->io.data_offset);
						// Napomena: U x86 podaci se smeštaju u memoriji po little endian poretku.
						(*data_in) = data;
					}
				}
				else if(v.run->io.port == 0x0278) {
					
				} 
				pthread_mutex_unlock(&io_mutex);
				continue;
			case KVM_EXIT_HLT:
				printf("KVM_EXIT_HLT\n");
				stop = 1;
				break;
			case KVM_EXIT_SHUTDOWN:
				printf("Shutdown\n");
				stop = 1;
				break;
			default:
				printf("Default - exit reason: %d\n", v.run->exit_reason);
				break;
    	}
  	}

	vm_destroy(&v);	
	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_mutex_init(&io_mutex, NULL);

	// for command line parsing
	size_t mem_size = 0;
	long page_size = -1;
	char *guest_paths[MAX_GUESTS] = {0};
    char *shared_files[MAX_SHARED_FILES] = {0}; 

	// 1. Define your long options
    static struct option long_options[] = {
        {"memory", required_argument, 0, 'm'},
        {"page",   required_argument, 0, 'p'},
        {"guest",  required_argument, 0, 'g'},
        {"file", required_argument, 0, 'f'},
        {0, 0, 0, 0} // End of the array
    };

    // 2. Create the short options string
    // "m:p:g:" means m, p, and g all require an argument (the colon)
    const char *short_opts = "m:p:g:f:";

    int guest_count = 0;
    int file_count = 0;
    int long_index = 0;

    enum parse_mode {
        PARSE_NONE,
        PARSE_MEM,
        PARSE_PAGE,
        PARSE_GUESTS,
        PARSE_FILES
    };

    enum parse_mode mode = PARSE_NONE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--memory") == 0) {
            mode = PARSE_MEM;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--page") == 0) {
            mode = PARSE_PAGE;
        } else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--guest") == 0) {
            mode = PARSE_GUESTS;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            mode = PARSE_FILES;
        } else if (argv[i][0] == '-') {
            // Unknown option
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        } else {
            // This is an argument, not an option
            switch (mode) {
                case PARSE_MEM:
                    mem_size = atol(argv[i]);
                    mode = PARSE_NONE;
                break;
                case PARSE_PAGE:
                    page_size = atol(argv[i]);
                    mode = PARSE_NONE;
                    break;
                case PARSE_GUESTS:
                    if (guest_count < MAX_GUESTS)
                        guest_paths[guest_count++] = argv[i];
                    break;
                case PARSE_FILES:
                    if (file_count < MAX_SHARED_FILES)
                        shared_files[file_count++] = argv[i];
                    break;
                case PARSE_NONE:
                    break;
            }
        }
    }

    // 3. Validation if every value was input
    if (mem_size == 0 || page_size == -1 || guest_count == 0) {
        fprintf(stderr, "Usage: %s -m <2|4|8>[KB] -p <4[KB]|2[MB]> -g <guest1.img> [guest2.img...] [-f file1...]\n", argv[0]);
        fprintf(stderr, "   or: %s --memory <2|4|8>[KB] --page <4[KB]|2[MB]> --guest <guest1.img> [guest2.img...] [-f file1...]\n", argv[0]);
        return 1;
    }

    // Validation for 2/4/8MB and 4KB/2MB
	if ((mem_size != 2 && mem_size != 4 && mem_size != 8) || (page_size != 2 && page_size != 4)) {
        fprintf(stderr, "Usage: %s -m <2|4|8>[KB] -p <4[KB]|2[MB]> -g <guest1.img> [guest2.img...] [-f file1...]\n", argv[0]);
        fprintf(stderr, "   or: %s --memory <2|4|8>[KB] --page <4[KB]|2[MB]> --guest <guest.img>[guest2.img...] [-f file1...]\n", argv[0]);
        return 1;
    }


	// Print vm setup
    printf("Starting VM with:\n");
    printf("  Memory: %zu MB\n", mem_size);
    printf("  Page Size: %ld", page_size); 
	if(page_size == 2) printf(" MB\n");
	else printf(" KB\n");
    printf("  Guests: ");
    for(int i = 0; i < guest_count; i++) {
        if(i == guest_count - 1) {
            printf("%s ", guest_paths[i]);
        	printf("\n");
        }
        else {
            printf("%s, ", guest_paths[i]);
        }
    }
    printf("  Shared files: ");
    for(int i = 0; i < file_count; i++) {
        if(i == file_count - 1) {
            printf("%s ", shared_files[i]);
        	printf("\n");
        }
        else {
            printf("%s, ", shared_files[i]);
        }
    }

	mem_size = mem_size << 20; // Convert mem_size to MB
	
	// START VM THREADS
	struct InitVMData *args[guest_count];
	pthread_t *vm_threads = (pthread_t*)malloc(guest_count * sizeof(pthread_t)); 
	for(int i = 0; i < guest_count; i++) {
		args[i] = (struct InitVMData *)malloc(sizeof(struct InitVMData));
		args[i]->mem_size = mem_size;
		args[i]->page_size = page_size;
		args[i]->guest_path = guest_paths[i];
		args[i]->file_count = file_count;
		args[i]->shared_files = shared_files;
    	if(pthread_create(&vm_threads[i], NULL, run_vm, args[i]) != 0) {
			perror("pthread_create error!\n");
			return -1;
		}

	}

	// JOIN ALL THREADS
    printf("All VMs running. Waiting for them to exit...\n");
    for (int i = 0; i < guest_count; i++) {
        pthread_join(vm_threads[i], NULL);
        printf("VM %d has finished.\n", i);
    }

	// FREE ALLOCATED MEMORY
	free(vm_threads);
    for(int i = 0; i < guest_count; i++) {
		free(args[i]);
	}
	pthread_mutex_destroy(&io_mutex);

    printf("All VMs have finished. Exiting hypervisor.\n");
	return 0;
}
