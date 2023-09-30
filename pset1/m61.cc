
#include "m61.hh"
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <sys/mman.h>
#include <map>
#include <list> // Include this to resolve the error


struct m61_metadata {
    size_t size;
};


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
static std::list<std::pair<void*, size_t>> free_blocks;


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


static void coalesce_freed_allocations() {
    auto it = freed_allocations.begin();
    while (it != freed_allocations.end()) {
        auto next_it = std::next(it);

        if (next_it != freed_allocations.end()) {
            // Check if the current and next freed allocations are adjacent
            if ((char*)it->first + it->second == next_it->first) {
                it->second += next_it->second; // Merge them
                freed_allocations.erase(next_it);
                continue; // Continue with the merged allocation
            }
        }

        // Move to the next allocation
        ++it;
    }
}

// Helper function to check contents preservation
void check_contents_preservation() {
    for (auto it = active_allocations.begin(); it != active_allocations.end(); ++it) {
        char* ptr = (char*)it->first;
        size_t sz = it->second;
        assert(memcmp(ptr, default_buffer.buffer + (ptr - default_buffer.buffer), sz) == 0);
    }
}
void* m61_malloc(size_t sz, const char* file, int line) {
    (void)file, (void)line;   // Avoid uninitialized variable warnings
    
    const size_t padding_size = 8; // for detecting wild writes
    size_t total_size = sizeof(m61_metadata) + sz + padding_size;
    
    // Check for overflow conditions
    if (sz == 0 || total_size < sz || (default_buffer.pos + total_size) < total_size) {
        ++gstats.nfail;
        gstats.fail_size += sz;
        return nullptr;
    }

    // Check if space is available in the buffer
    if (default_buffer.pos + total_size > default_buffer.size) {
        ++gstats.nfail;
        gstats.fail_size += sz;
        return nullptr;
    }

    m61_metadata* metadata = reinterpret_cast<m61_metadata*>(&default_buffer.buffer[default_buffer.pos]);
    metadata->size = sz; // Store size in metadata
    char* ptr = reinterpret_cast<char*>(metadata + 1);
    default_buffer.pos += total_size;

    memset(ptr + sz, 'B', padding_size); // Initialize padding bytes.
    
    // Ensure there is only one active allocation
    static bool active_allocation = false;
    if (active_allocation) {
        fprintf(stderr, "MEMORY BUG: %s:%d: detected multiple active allocations\n", file, line);
        exit(EXIT_FAILURE);
    }
    active_allocation = true;
    
    // Track active allocations
    active_allocations[ptr] = sz;

    // Update statistics
    gstats.total_size += sz;
    ++gstats.ntotal;
    ++gstats.nactive;
    gstats.active_size += sz;
    
    uintptr_t allocation_address = (uintptr_t)ptr;
    if (gstats.heap_min > allocation_address) gstats.heap_min = allocation_address;
    if (gstats.heap_max < allocation_address + sz) gstats.heap_max = allocation_address + sz;
    
    check_contents_preservation();

    // Reset active allocation state when successful
    active_allocation = false;

    return ptr;
}


/// m61_free(ptr, file, line)
///    Frees the memory allocation pointed to by `ptr`. If `ptr == nullptr`,
///    does nothing. Otherwise, `ptr` must point to a currently active
///    allocation returned by `m61_malloc`. The free was called at location
void m61_free(void* ptr, const char* file, int line) {
    if (ptr == nullptr) {
        return;
    }

    auto it = active_allocations.find(ptr);
    if (it == active_allocations.end()) {
        // Check if the pointer is not in active_allocations and not in the default buffer
        if ((uintptr_t)ptr < (uintptr_t)default_buffer.buffer || (uintptr_t)ptr >= (uintptr_t)default_buffer.buffer + default_buffer.size) {
            // The pointer is not in active_allocations and not in the default buffer; this is an error
            fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not in heap\n", file, line, ptr);
            exit(EXIT_FAILURE);
        } else if (freed_allocations.find(ptr) != freed_allocations.end()) {
            // The pointer is in freed_allocations (double free detected)
            fprintf(stderr, "MEMORY BUG???: invalid free of pointer %p, double free\n", ptr);
            exit(EXIT_FAILURE);
        } else {
            // The pointer is in the default buffer but not allocated
            fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n", file, line, ptr);
            exit(EXIT_FAILURE);
        }
    }

    // Extracting metadata and size.
    m61_metadata* metadata = reinterpret_cast<m61_metadata*>(ptr) - 1;
    size_t sz = metadata->size;

    // Check padding bytes for boundary write errors.
    char* data_ptr = reinterpret_cast<char*>(ptr);
    for (size_t i = 0; i < 8; i++) {
        if (data_ptr[sz + i] != 'B') {
            fprintf(stderr, "MEMORY BUG: %s:%d: detected wild write during free of pointer %p\n", file, line, ptr);
            exit(EXIT_FAILURE);
        }
    }

    active_allocations.erase(it);
    freed_allocations[ptr] = sz;

    --gstats.nactive;
    gstats.active_size -= sz;
    
    coalesce_freed_allocations();
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