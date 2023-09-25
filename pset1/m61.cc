#include "m61.hh"
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <sys/mman.h>
#include <map>


struct m61_memory_buffer {
    char* buffer;
    size_t pos = 0;
    size_t size = 8 << 20; /* 8 MiB */

    m61_memory_buffer();
    ~m61_memory_buffer();
};

static m61_memory_buffer default_buffer;
static std::map<void*, size_t> freed_allocations;
static std::map<void*, size_t> active_allocations;


m61_memory_buffer::m61_memory_buffer() {
    void* buf = mmap(nullptr,    // Place the buffer at a random address
        this->size,              // Buffer should be 8 MiB big
        PROT_WRITE,              // We want to read and write the buffer
        MAP_ANON | MAP_PRIVATE, -1, 0);
                                 // We want memory freshly allocated by the OS
    assert(buf != MAP_FAILED);
    this->buffer = (char*) buf;
}

m61_memory_buffer::~m61_memory_buffer() {
    munmap(this->buffer, this->size);
}


/// m61_malloc(sz, file, line)
///    Returns a pointer to `sz` bytes of freshly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    return either `nullptr` or a pointer to a unique allocation.
///    The allocation request was made at source code location `file`:`line`.


static m61_statistics gstats = {
    .nactive = 0,
    .active_size = 0,
    .ntotal = 0,
    .total_size = 0,
    .nfail = 0,
    .fail_size = 0,
    .heap_min = SIZE_MAX,
    .heap_max = 0
};
void* m61_malloc(size_t sz, const char* file, int line) {
    (void)file, (void)line; // Avoid uninitialized variable warnings

    // Try to find a suitable freed allocation
    for (auto it = freed_allocations.begin(); it != freed_allocations.end(); ++it) {
        if (it->second >= sz) {
            void* ptr = it->first;
            freed_allocations.erase(it);

            // Track active allocations
            active_allocations[ptr] = sz;

            // Update heap_min and heap_max
            uintptr_t allocation_address = (uintptr_t)ptr;
            if (gstats.heap_min > allocation_address)
                gstats.heap_min = allocation_address;
            if (gstats.heap_max < allocation_address + sz)
                gstats.heap_max = allocation_address + sz;

            // Track memory allocation statistics
            ++gstats.nactive;
            gstats.active_size += sz;

            return ptr;
        }
    }

    // If no suitable freed allocation is found, proceed with a new allocation
    if (default_buffer.pos + sz > default_buffer.size || default_buffer.pos + sz < default_buffer.pos) {
        // Not enough space left in the default buffer for allocation or sz is too large
        ++gstats.nfail;
        gstats.fail_size += sz; // Update fail_size with the requested size.
        return nullptr;
    }

    // Otherwise, there is enough space; claim the next `sz` bytes
    void* ptr = &default_buffer.buffer[default_buffer.pos];
    default_buffer.pos += sz;

    // Track active allocations
    active_allocations[ptr] = sz;

    // Update heap_min and heap_max
    uintptr_t allocation_address = (uintptr_t)ptr;
    if (gstats.heap_min > allocation_address)
        gstats.heap_min = allocation_address;
    if (gstats.heap_max < allocation_address + sz)
        gstats.heap_max = allocation_address + sz;

    // Track memory allocation statistics
    ++gstats.nactive;
    gstats.total_size += sz; // Update total_size with the requested size.
    gstats.active_size += sz; // Update active_size with the requested size.
    ++gstats.ntotal;

    return ptr;
}


static void coalesce_freed_allocations() {
    for (auto it = freed_allocations.begin(); it != freed_allocations.end(); ++it) {
        auto next_it = std::next(it);

        if (next_it != freed_allocations.end()) {
            // Check if the current and next freed allocations are adjacent
            if ((char*)it->first + it->second == next_it->first) {
                it->second += next_it->second; // Merge them
                freed_allocations.erase(next_it);
            }
        }
    }
}


void m61_free(void* ptr, const char* file, int line) {
    if (ptr == nullptr) {
        return; // Do nothing if ptr is nullptr
    }

    // Calculate the size of the allocation being freed directly
    size_t sz = active_allocations[ptr];

    // Remove the freed allocation from active_allocations
    active_allocations.erase(ptr);

    // Add the freed allocation to freed_allocations
    freed_allocations[ptr] = sz;

    // Track memory deallocation statistics
    gstats.active_size -= sz;
    --gstats.nactive;

    // Call coalesce function after each free
    coalesce_freed_allocations();

    // Rest of your m61_free implementation
    (void)file, (void)line;
}

/// m61_calloc(count, sz, file, line)
///    Returns a pointer a fresh dynamic memory allocation big enough to
///    hold an array of `count` elements of `sz` bytes each. Returned
///    memory is initialized to zero. The allocation request was at
///    location `file`:`line`. Returns `nullptr` if out of memory; may
///    also return `nullptr` if `count == 0` or `size == 0`.

void* m61_calloc(size_t count, size_t sz, const char* file, int line) {
    // Calculate the total size required for calloc
    size_t total_size = count * sz;

    // Check for potential overflow
    if (count != 0 && sz != 0 && total_size / sz != count) {
        ++gstats.nfail;
        return nullptr;
    }

    void* ptr = m61_malloc(total_size, file, line);
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    return ptr;
}


/// m61_get_statistics()
///    Return the current memory statistics.

m61_statistics m61_get_statistics() {
    return gstats;
}


/// m61_print_statistics()
///    Prints the current memory statistics.

void m61_print_statistics() {
    m61_statistics stats = m61_get_statistics();
    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_print_leak_report()
///    Prints a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_print_leak_report() {
    // Your code here.
}
