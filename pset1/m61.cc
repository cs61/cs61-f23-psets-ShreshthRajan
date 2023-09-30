#include "m61.hh"
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <sys/mman.h>
#include <map>
#include <list>

struct m61_metadata {
    size_t size;
    const char* file;
    int line;
};

struct m61_memory_buffer {
    char* buffer;
    size_t pos = 0;
    size_t size = 8 << 20; /* 8 MiB */

    m61_memory_buffer();
    ~m61_memory_buffer();
};

static void* active_allocation = nullptr;
static m61_memory_buffer default_buffer;
static std::map<void*, m61_metadata> freed_allocations;
static size_t total_allocated_size = 0;

static std::map<void*, m61_metadata> active_allocations;
static std::list<std::pair<void*, size_t>> free_blocks;

m61_memory_buffer::m61_memory_buffer() {
    void* buf = mmap(nullptr, this->size, PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
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
            if ((char*)it->first + it->second.size == next_it->first) {
                it->second.size += next_it->second.size;
                freed_allocations.erase(next_it);
                continue;
            }
        }

        ++it;
    }
}

void check_contents_preservation() {
    for (auto it = active_allocations.begin(); it != active_allocations.end(); ++it) {
        char* ptr = (char*)it->first;
        size_t sz = it->second.size;
        assert(memcmp(ptr, default_buffer.buffer + (ptr - default_buffer.buffer), sz) == 0);
    }
}



void* m61_malloc(size_t sz, const char* file, int line) {
    (void)file, (void)line;

    const size_t padding_size = 8;
    size_t total_size = sizeof(m61_metadata) + sz + padding_size;

    if (sz == 0 || total_size < sz || (default_buffer.pos + total_size) < total_size) {
        ++gstats.nfail;
        gstats.fail_size += sz;
        return nullptr;
    }

    if (default_buffer.pos + total_size > default_buffer.size) {
        ++gstats.nfail;
        gstats.fail_size += sz;
        return nullptr;
    }

    m61_metadata* metadata = reinterpret_cast<m61_metadata*>(&default_buffer.buffer[default_buffer.pos]);
    metadata->size = sz;
    metadata->file = file;
    metadata->line = line;
    char* ptr = reinterpret_cast<char*>(metadata + 1);
    default_buffer.pos += total_size;

    memset(ptr + sz, 'B', padding_size);

    if (active_allocation) {
        fprintf(stderr, "MEMORY BUG: %s:%d: detected multiple active allocations\n", file, line);
        exit(EXIT_FAILURE);
    }
    active_allocation = ptr;

    active_allocations[ptr] = *metadata;

    gstats.total_size += sz;
    ++gstats.ntotal;
    ++gstats.nactive;
    gstats.active_size += sz;

    uintptr_t allocation_address = (uintptr_t)ptr;
    if (gstats.heap_min > allocation_address) gstats.heap_min = allocation_address;
    if (gstats.heap_max < allocation_address + sz) gstats.heap_max = allocation_address + sz;

    check_contents_preservation();

    active_allocation = nullptr;

    return ptr;
}

void m61_free(void* ptr, const char* file, int line) {
    if (ptr == nullptr) {
        return;
    }

    auto it = active_allocations.find(ptr);
    if (it == active_allocations.end()) {
        if ((uintptr_t)ptr < (uintptr_t)default_buffer.buffer || (uintptr_t)ptr >= (uintptr_t)default_buffer.buffer + default_buffer.size) {
            fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not in heap\n", file, line, ptr);
            exit(EXIT_FAILURE);
        } else if (freed_allocations.find(ptr) != freed_allocations.end()) {
            fprintf(stderr, "MEMORY BUG???: invalid free of pointer %p, double free\n", ptr);
            exit(EXIT_FAILURE);
        } else {
            fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n", file, line, ptr);
            exit(EXIT_FAILURE);
        }
    }

    m61_metadata metadata = it->second;
    size_t sz = metadata.size;

    char* data_ptr = reinterpret_cast<char*>(ptr);
    for (size_t i = 0; i < 8; i++) {
        if (data_ptr[sz + i] != 'B') {
            fprintf(stderr, "MEMORY BUG: %s:%d: detected wild write during free of pointer %p\n", file, line, ptr);
            exit(EXIT_FAILURE);
        }
    }

    active_allocations.erase(it);
    freed_allocations[ptr] = metadata;

    --gstats.nactive;
    gstats.active_size -= sz;

    coalesce_freed_allocations();
}

void* m61_calloc(size_t count, size_t sz, const char* file, int line) {
    size_t total_size = count * sz;

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

m61_statistics m61_get_statistics() {
    return gstats;
}



void m61_print_statistics() {
    m61_statistics stats = m61_get_statistics();
    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}

void m61_print_leak_report() {
    for (const auto& allocation : active_allocations) {
        printf("LEAK CHECK: %s:%d: allocated object %p with size %zu\n",
               allocation.second.file, allocation.second.line, allocation.first, allocation.second.size);
    }
}
