#include "kernel.hh"
#include "k-apic.hh"
#include "k-vmiter.hh"
#include "obj/k-firstprocess.h"
#include "atomic.hh"

// kernel.cc
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

proc ptable[PID_MAX];           // array of process descriptors
                                // Note that `ptable[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static atomic<unsigned long> ticks; // # timer interrupts so far


// Memory state - see `kernel.hh`
physpageinfo physpages[NPAGES];


[[noreturn]] void schedule();
[[noreturn]] void run(proc* p);
void exception(regstate* regs);
uintptr_t syscall(regstate* regs);
void memshow();


static void process_setup(pid_t pid, const char* program_name);

// kernel_start(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

void kernel_start(const char* command) {
    // initialize hardware
    init_hardware();
    log_printf("Starting WeensyOS\n");

    ticks = 1;
    init_timer(HZ);

    // clear screen
    console_clear();

    // re-initialize the page table
    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int kernel_perm = PTE_P | PTE_W;
        int user_process_perm = PTE_P | PTE_W | PTE_U;
        if (addr == 0) {
            // nullptr is completely inaccessible
            kernel_perm = 0;
            user_process_perm = 0;
        }
        // identity mapping
        int r;
        if (addr >= 0x100000 || addr == 0xB8000) {
            r = vmiter(kernel_pagetable, addr).try_map(addr, user_process_perm);
        } else {
            r = vmiter(kernel_pagetable, addr).try_map(addr, kernel_perm);
        }
        assert(r == 0); // mappings during kernel_start MUST NOT fail
                        // (Note that later mappings might fail!!)
    }
    
    // set up process descriptors
    for (pid_t i = 0; i < PID_MAX; i++) {
        ptable[i].pid = i;
        ptable[i].state = P_FREE;
    }
    if (!command) {
        command = WEENSYOS_FIRST_PROCESS;
    }
    if (!program_image(command).empty()) {
        process_setup(1, command);
    } else {
        process_setup(1, "allocator");
        process_setup(2, "allocator2");
        process_setup(3, "allocator3");
        process_setup(4, "allocator4");
    }

    // switch to first process using run()
    run(&ptable[1]);
}


// kalloc(sz)
//    Kernel physical memory allocator. Allocates at least `sz` contiguous bytes
//    and returns a pointer to the allocated memory, or `nullptr` on failure.
//    The returned pointerâ€™s address is a valid physical address, but since the
//    WeensyOS kernel uses an identity mapping for virtual memory, it is also a
//    valid virtual address that the kernel can access or modify.
//
//    The allocator selects from physical pages that can be allocated for
//    process use (so not reserved pages or kernel data), and from physical
//    pages that are currently unused (`physpages[N].refcount == 0`).
//
//    On WeensyOS, `kalloc` is a page-based allocator: if `sz > PAGESIZE`
//    the allocation fails; if `sz < PAGESIZE` it allocates a whole page
//    anyway.
//
//    The returned memory is initially filled with 0xCC, which corresponds to
//    the `int3` instruction. Executing that instruction will cause a `PANIC:
//    Unhandled exception 3!` This may help you debug.

void* kalloc(size_t sz) {
    if (sz > PAGESIZE) {
        return nullptr;
    }

    // identifies which free page to allocate 
    int pageno = 0;
    // When the loop starts from page 0, `kalloc` returns the first free page.
    // Alternate search strategies can be faster and/or expose bugs elsewhere.
    // This initialization returns a random free page:
    //     int pageno = rand(0, NPAGES - 1);
    // This initialization remembers the most-recently-allocated page and
    // starts the search from there:
    //     static int pageno = 0;

    for (int tries = 0; tries != NPAGES; ++tries) {
        uintptr_t pa = pageno * PAGESIZE;
        if (allocatable_physical_address(pa)
            && physpages[pageno].refcount == 0) {
            ++physpages[pageno].refcount;
            memset((void*) pa, 0xCC, PAGESIZE);
            return (void*) pa;
        }
        pageno = (pageno + 1) % NPAGES;
    }

    return nullptr;
}

// kfree(kptr)
//    Free `kptr`, which must have been previously returned by `kalloc`.
//    If `kptr == nullptr` does nothing.

void kfree(void* kptr) {
    (void) kptr;
    if (kptr != nullptr) {
        // decrement the ref count, this is opposite of what kalloc does
        int pageno = ((uintptr_t) kptr) / PAGESIZE;
        physpages[pageno].refcount--;
    }
}

// process_setup(pid, program_name)
//    Load application program `program_name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, const char *program_name) {
    init_process(&ptable[pid], 0);

    // initialize process page table
    ptable[pid].pagetable = kalloc_pagetable();

    // obtain reference to program image
    // (The program image models the process executable.)
    program_image pgm(program_name);

    // allocate and map process memory as specified in program image    
    for (vmiter original_kernel_iter = vmiter(kernel_pagetable, PAGESIZE), new_pid_iter = vmiter(ptable[pid].pagetable, PAGESIZE); new_pid_iter.va() < PROC_START_ADDR;
original_kernel_iter += PAGESIZE, new_pid_iter += PAGESIZE) {
    assert(new_pid_iter.try_map(original_kernel_iter.va(), original_kernel_iter.perm()) >= 0);
    }

    // allocate and map process memory as specified in program image
    for (auto seg = pgm.begin(); seg != pgm.end(); ++seg) {
        for (uintptr_t a = round_down(seg.va(), PAGESIZE); a < seg.va() + seg.size(); a += PAGESIZE) {
            // `a` is the process virtual address for the next code or data page
            // (The handout code requires that the corresponding physical
            // address is currently free.)
            // update new mappings if segment is user adaptable 

            void* phys_addr = kalloc(PAGESIZE);
            assert(phys_addr != nullptr);

            if (seg.writable()) {
                assert(vmiter(ptable[pid].pagetable, a).try_map(phys_addr, PTE_P | PTE_W | PTE_U) >= 0);
            } else {
                assert(vmiter(ptable[pid].pagetable, a).try_map(phys_addr, PTE_P | PTE_U) >= 0);
            }
            memset(phys_addr, 0, seg.size());
            memcpy(phys_addr, seg.data() + (a - seg.va()), seg.data_size());
        }
    }

    // Mark entry point
    ptable[pid].regs.reg_rip = pgm.entry();

    // Allocate and map stack segment
    // Compute process virtual address for stack page
    uintptr_t stack_addr = MEMSIZE_VIRTUAL - PAGESIZE;

    // Get new physical address
    void* phys_addr = kalloc(PAGESIZE);
    assert(phys_addr != nullptr);

    // Map virtual to physical address with all permissions
    assert(vmiter(ptable[pid].pagetable, stack_addr).try_map(phys_addr, PTE_PWU) >= 0);

    ptable[pid].regs.reg_rsp = stack_addr + PAGESIZE;

    // mark process as runnable
    ptable[pid].state = P_RUNNABLE;
}

// exception(regs)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `regs`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (in
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception().
//
//    Note that hardware interrupts are disabled when the kernel is running.

void exception(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: exception %d at rip %p\n",
                current->pid, regs->reg_intno, regs->reg_rip); */

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if (regs->reg_intno != INT_PF || (regs->reg_errcode & PTE_U)) {
        memshow();
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER:
        ++ticks;
        lapicstate::get().ack();
        schedule();
        break;                  /* will not be reached */

    case INT_PF: {
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PTE_W
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PTE_P
                ? "protection problem" : "missing page";

        if (!(regs->reg_errcode & PTE_U)) {
            proc_panic(current, "Kernel page fault on %p (%s %s, rip=%p)!\n",
                       addr, operation, problem, regs->reg_rip);
        }
        error_printf(CPOS(24, 0), 0x0C00,
                     "Process %d page fault on %p (%s %s, rip=%p)!\n",
                     current->pid, addr, operation, problem, regs->reg_rip);
        current->state = P_FAULTED;
        break;
    }

    default:
        proc_panic(current, "Unhandled exception %d (rip=%p)!\n",
                   regs->reg_intno, regs->reg_rip);

    }


    // Return to the current process (or run something else).
    if (current->state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


int syscall_page_alloc(uintptr_t addr);

int syscall_fork();
int syscall_exit();
void free_everything(x86_64_pagetable* pt);


// syscall(regs)
//    Handle a system call initiated by a `syscall` instruction.
//    The processâ€™s register values at system call time are accessible in
//    `regs`.
//
//    If this function returns with value `V`, then the user process will
//    resume with `V` stored in `%rax` (so the system call effectively
//    returns `V`). Alternately, the kernel can exit this function by
//    calling `schedule()`, perhaps after storing the eventual system call
//    return value in `current->regs.reg_rax`.
//
//    It is only valid to return from this function if
//    `current->state == P_RUNNABLE`.
//
//    Note that hardware interrupts are disabled when the kernel is running.

uintptr_t syscall(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: syscall %d at rip %p\n",
                  current->pid, regs->reg_rax, regs->reg_rip); */

    // Show the current cursor location and memory state.
    console_show_cursor(cursorpos);
    memshow();

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_rax) {

    case SYSCALL_PANIC:
        user_panic(current);
        break; // will not be reached

    case SYSCALL_GETPID:
        return current->pid;

    case SYSCALL_YIELD:
        current->regs.reg_rax = 0;
        schedule();             // does not return

    case SYSCALL_PAGE_ALLOC:
        return syscall_page_alloc(current->regs.reg_rdi);

    // this is defined in lib.hh
    case SYSCALL_FORK:
        current->regs.reg_rax = 0;
        return syscall_fork();

    case SYSCALL_EXIT:
        return syscall_exit();

    default:
        proc_panic(current, "Unhandled system call %ld (pid=%d, rip=%p)!\n",
                   regs->reg_rax, current->pid, regs->reg_rip);

    }

    panic("Should not get here!\n");
}

// syscall_page_alloc(addr)
// Handles the SYSCALL_PAGE_ALLOC system call. This function
// should implement the specification for `sys_page_alloc`
// in `u-lib.hh` (but in the handout code, it does not).

int syscall_page_alloc(uintptr_t addr) {
    if (addr % PAGESIZE != 0 || addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL) {
        return -1;
    }


    // generate new physical memory address from virtual address with necesarry permissions

    void* phys_addr = kalloc (PAGESIZE);
    if (phys_addr == nullptr) {
        return -1;
    }
    if (vmiter(current->pagetable, addr).try_map(phys_addr, PTE_P | PTE_W | PTE_U) < 0) {
        kfree(phys_addr);
        return -1;
    }
    // set all memory to 0 
    memset (phys_addr, 0, PAGESIZE);
    return 0;
}

// syscall_fork()
// Handles the SYSCALL_FORK system call. This function
// should implement the specification for `sys_fork`
// in `u-lib.hh`.
int syscall_fork() {

    // look for P_FREE process slot in ptable[]
    proc* child_process = nullptr;
    pid_t child_pid;
    for (pid_t i = 1; i < PID_MAX; ++i) {
       // Make process object that represents process descriptor 
        proc* process = &ptable[i];
        if(process->state == P_FREE) {
            child_process = process;
            child_pid = i;
            break;
        }
    }
    if (child_process == nullptr) {
        return -1;
    }

    child_process->pid = child_pid;

    child_process->pagetable = kalloc_pagetable();
    if (child_process->pagetable == nullptr) return -1;

    vmiter pid_iter = vmiter(current->pagetable, PAGESIZE);
    for (; pid_iter.va() < MEMSIZE_VIRTUAL; pid_iter += PAGESIZE) {
        if (pid_iter.va() >= PROC_START_ADDR){
            // check permisssions of the current pid_iter object
            int permissions = pid_iter.perm();
            if ((permissions & PTE_W)) {
                // allocate a new physical page P
                void* P = kalloc(PAGESIZE);
                if (P == nullptr) {
                    free_everything(child_process->pagetable);
                    return -1;
                }

                // map page P at address V in the child page table
                int r = vmiter(child_process->pagetable, pid_iter.va()).try_map(P, permissions);
                if (r < 0) {
                    kfree(P);
                    free_everything(child_process->pagetable);
                    return -1;
                }

                // copy all data from parent into P 
                memcpy(P, (void*) pid_iter.pa(), PAGESIZE);
            } else if (permissions & PTE_U) {
                void* phys_addr = reinterpret_cast<void*>(pid_iter.pa());
                assert(vmiter(child_process->pagetable, pid_iter.va()).try_map(phys_addr, permissions) >= 0);
                ++physpages[pid_iter.pa() / PAGESIZE].refcount;
            }
        } else {
            int r = vmiter(child_process->pagetable, pid_iter.va()).try_map(vmiter(current->pagetable, pid_iter.va()).pa(), vmiter(current->pagetable, pid_iter.va()).perm());
            if (r < 0){
                free_everything(child_process->pagetable);
                return -1;
            }
        }
    }

    // Initialize child_process registers as the parent registers
    child_process->regs = current->regs;
    child_process->state = P_RUNNABLE;
    return child_pid;
}

void free_everything(x86_64_pagetable *pt) {
    for (vmiter it(pt, 0); it.va() < MEMSIZE_VIRTUAL; it.next()) {
        if (it.user() && it.pa() != CONSOLE_ADDR) kfree((void*) it.pa());
    }

    // ptiter iterates through the physical memory

    for (ptiter it(pt); it.va() < MEMSIZE_VIRTUAL; it.next()) {
        kfree((void*) it.pa());
    }
    kfree(pt);
}

int syscall_exit() {
    // use vmiter to iterate through the virtual memory
    free_everything(current->pagetable);
    current->state = P_FREE;
    schedule();
}

// schedule
// Pick the next process to run and then run it.
// If there are no runnable processes, spins forever.

void schedule() {
    pid_t pid = current->pid;
    for (unsigned spins = 1; true; ++spins) {
        pid = (pid + 1) % PID_MAX;
        if (ptable[pid].state == P_RUNNABLE) {
            run(&ptable[pid]);
        }

        // If Control-C was typed, exit the virtual machine.
        check_keyboard();

        // If spinning forever, show the memviewer.
        if (spins % (1 << 12) == 0) {
            memshow();
            log_printf("%u\n", spins);
        }
    }
}


// run(p)
// Run process `p`. This involves setting `current = p` and calling
// `exception_return` to restore its page table and registers.

void run(proc* p) {
    assert(p->state == P_RUNNABLE);
    current = p;

    // Check the process's current pagetable.
    check_pagetable(p->pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(p);

    // should never get here
    while (true) {
    }
}


// memshow()
// Draw a picture of memory (physical and virtual) on the CGA console.
// Switches to a new process's virtual memory map every 0.25 sec.
// Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.

void memshow() {
    static unsigned last_ticks = 0;
    static int showing = 0;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        showing = (showing + 1) % PID_MAX;
    }

    proc* p = nullptr;
    for (int search = 0; !p && search < PID_MAX; ++search) {
        if (ptable[showing].state != P_FREE
        && ptable[showing].pagetable) {
            p = &ptable[showing];
        } else {
            showing = (showing + 1) % PID_MAX;
        }
    }

    console_memviewer(p);
    if (!p) {
        console_printf(CPOS(10, 26), 0x0F00, " VIRTUAL ADDRESS SPACE\n"
        " [All processes have exited]\n"
        "\n\n\n\n\n\n\n\n\n\n\n");
    }
}