#include "io61.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <cerrno>
#include <sys/mman.h>

// io61.cc
//    YOUR CODE HERE!


// io61_file
//    Data structure for io61 file wrappers. Add your own stuff.


struct io61_file
{
    int fd = -1;                 // File descriptor
    static constexpr off_t bufsize = 8192; // Result of trying different buffer sizes
    unsigned char bufcache[bufsize];

    // "tags" describe cache's content with offsets
    off_t tag;
    off_t end_tag;
    off_t pos_tag;
    int mode;

    unsigned char *file_data; // Pointer to be returned for mmap
    size_t file_size;
    size_t mmap_pos; // Offset
};

// io61_fdopen(fd, mode)
//    Returns a new io61_file for file descriptor `fd`. `mode` is either
//    O_RDONLY for a read-only file or O_WRONLY for a write-only file.
//    You need not support read/write files.

io61_file *io61_fdopen(int fd, int mode)
{
    assert(fd >= 0);
    io61_file *f = new io61_file;
    f->fd = fd;
    f->mode = mode;
    f->pos_tag = f->end_tag = f->tag = f->mmap_pos = 0;
    f->file_size = io61_filesize(f); // Setting the file_size variable

    if (f->file_size != (size_t)-1)
    {
        f->file_data = (unsigned char *)mmap(nullptr, f->file_size, PROT_READ, MAP_SHARED, f->fd, 0); // Mmap the file
    }
    else
    {
        f->file_data = (unsigned char *)MAP_FAILED; // Claim that the map failed if file_size = 1
    }
    return f;
}

// io61_close(f)
//    Closes the io61_file `f` and releases all its resources.

int io61_close(io61_file *f)
{
    if (f->file_data != (unsigned char *)MAP_FAILED && f->file_data != nullptr) // See if the file was mapped
    {
        munmap(f->file_data, f->file_size);
    }
    else
    {
        io61_flush(f);
    }
    int r = close(f->fd);
    delete f;
    return r;
}

// io61_fill(f)
// Fills read cache with data from 'end_tag'
int io61_fill(io61_file *f)
{
    // Only called for read caches.

    // Check invariants.
    if (!(f->tag <= f->pos_tag && f->pos_tag <= f->end_tag))
    {
        return -1;
    }
    if (!(f->end_tag - f->pos_tag <= f->bufsize))
    {
        return -1;
    }

    // Reset the cache to empty.
    f->tag = f->pos_tag = f->end_tag;

    // Read data.
    ssize_t n;
    while ((n = read(f->fd, f->bufcache, f->bufsize)) >= 0)
    {
        if (n == 0)
        {
            break;
        }
        f->end_tag = f->tag + n;
        return 0;
    }
    return -1;
}

// io61_readc(f)
//    Reads a single (unsigned) byte from `f` and returns it. Returns EOF,
//    which equals -1, on end of file or error.

int io61_readc(io61_file *f)
{
    int ch;
    if (f->file_data != (unsigned char *)MAP_FAILED)
    {
        if (f->mmap_pos >= f->file_size)
        {
            return -1;
        }
        ch = f->file_data[f->mmap_pos];
        f->mmap_pos += 1;
        return ch;
    }
    if (f->pos_tag == f->end_tag)
    {
        int r = io61_fill(f);
        assert(r != 1);
        if (f->end_tag == f->pos_tag)
        {
            return -1;
        }
    }
    ch = f->bufcache[f->pos_tag - f->tag];
    f->pos_tag++;
    return ch;
}

// io61_read(f, buf, sz)
//    Reads up to `sz` bytes from `f` into `buf`. Returns the number of
//    bytes read on success. Returns 0 if end-of-file is encountered before
//    any bytes are read, and -1 if an error is encountered before any
//    bytes are read.
//
//    Note that the return value might be positive, but less than `sz`,
//    if end-of-file or error is encountered before all `sz` bytes are read.
//    This is called a “short read.”

ssize_t io61_read(io61_file *f, unsigned char *buf, size_t sz)
{
    if (f->file_data != (unsigned char *)MAP_FAILED)
    {
        if (f->mmap_pos >= f->file_size)
        {
            return -1;
        }
        if (sz + f->mmap_pos > f->file_size)
        {
            sz = f->file_size - f->mmap_pos;
        }
        memcpy(buf, &f->file_data[f->mmap_pos], sz);
        f->mmap_pos += sz;
        return sz;
    }

    // Check invariants.
    assert(f->tag <= f->pos_tag && f->pos_tag <= f->end_tag);
    assert(f->end_tag - f->pos_tag <= f->bufsize);

    size_t pos = 0;
    while (pos < sz)
    {
        if (f->pos_tag == f->end_tag)
        {
            io61_fill(f);
            if (f->pos_tag == f->end_tag)
            {
                break;
            }
        }

        int mem_size = std::min((int)(f->end_tag - f->pos_tag), (int)(sz - pos));
        memcpy(&buf[pos], &f->bufcache[f->pos_tag - f->tag], mem_size);
        f->pos_tag += mem_size;
        pos += mem_size;
    }
    return pos;
}

// io61_writec(f)
//    Write a single character `c` to `f` (converted to unsigned char).
//    Returns 0 on success and -1 on error.

int io61_writec(io61_file *f, int ch)
{
    unsigned char buf[1];
    buf[0] = ch;
    ssize_t nw = io61_write(f, buf, 1);
    if (nw == 1)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

// io61_write(f, buf, sz)
//    Writes `sz` characters from `buf` to `f`. Returns `sz` on success.
//    Can write fewer than `sz` characters when there is an error, such as
//    a drive running out of space. In this case io61_write returns the
//    number of characters written, or -1 if no characters were written
//    before the error occurred.

ssize_t io61_write(io61_file *f, const unsigned char *buf, size_t sz)
{
    // Check invariants.
    assert(f->tag <= f->pos_tag && f->pos_tag <= f->end_tag);
    assert(f->end_tag - f->pos_tag <= f->bufsize);

    // Write cache invariant.
    assert(f->pos_tag == f->end_tag);

    size_t pos = 0;
    while (pos < sz)
    {
        if (f->end_tag == f->tag + f->bufsize)
        {
            if (io61_flush(f) == -1)
            {
                return -1;
            }
        }

        int mem_size = std::min((int)(f->bufsize + f->tag - f->end_tag), (int)(sz - pos));
        memcpy(&f->bufcache[f->pos_tag - f->tag], &buf[pos], mem_size);
        f->pos_tag += mem_size;
        f->end_tag += mem_size;
        pos += mem_size;
    }
    return pos;
}

// io61_flush(f)
//    If `f` was opened write-only, `io61_flush(f)` forces a write of any
//    cached data written to `f`. Returns 0 on success; returns -1 if an error
//    is encountered before all cached data was written.
//
//    If `f` was opened read-only, `io61_flush(f)` returns 0. It may also
//    drop any data cached for reading.

int io61_flush(io61_file *f)
{
    // Check invariants.
    if (!(f->tag <= f->pos_tag && f->pos_tag <= f->end_tag))
    {
        return -1;
    }
    if (!(f->end_tag - f->pos_tag <= f->bufsize))
    {
        return -1;
    }

    // Cache invariant.
    if (!(f->pos_tag == f->end_tag))
    {
        return -1;
    }

    if (f->mode == O_RDONLY)
    {
        return 0;
    }

    // Track the position where the write left off in the cache buffer.
    size_t pos = 0;

    while ((long long)pos < (f->pos_tag) - (f->tag))
    {
        ssize_t n = write(f->fd, f->bufcache + pos, f->pos_tag - f->tag - pos);

        if (n < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
            {
                continue; // Restartable errors, continue writing.
            }
            else
            {
                return -1; // Permanent error, return -1.
            }
        }

        pos += n;
    }

    // Update the tag to reflect the current position.
    f->tag += pos;

    return 0;
}

// io61_seek(f, off)
//    Changes the file pointer for file `f` to `off` bytes into the file.
//    Returns 0 on success and -1 on failure.

int io61_seek(io61_file *f, off_t pos)
{
    if (f->file_data != (unsigned char *)MAP_FAILED)
    {
        if (pos < 0 || (int)pos >= (int)f->file_size)
        {
            return -1;
        }
        f->mmap_pos = pos;
        return 0;
    }
    off_t alignpos = pos - (pos % 8192);
    if (f->tag <= pos && pos < f->end_tag)
    { // Check if pos is inside the cache, if so, change the pos_tag
        f->pos_tag = pos;
        return 0;
    }
    else if (f->mode == O_RDONLY)
    {
        off_t r = lseek(f->fd, (off_t)alignpos, SEEK_SET);
        if (r < 0)
        {
            return -1;
        }
        f->pos_tag = alignpos;
        f->end_tag = alignpos;
        f->tag = alignpos;

        io61_fill(f);

        if (f->end_tag < pos)
        {
            return -1;
        }
        f->pos_tag = pos;
        return 0;
    }
    else
    {
        io61_flush(f);
        off_t r = lseek(f->fd, pos, SEEK_SET);
        if (r != pos)
        {
            return -1;
        }
        f->tag = pos;
        f->end_tag = pos;
        f->pos_tag = pos;
        return 0;
    }
}

// You shouldn't need to change these functions.

// io61_open_check(filename, mode)
//    Opens the file corresponding to `filename` and returns its io61_file.
//    If `!filename`, returns either the standard input or the
//    standard output, depending on `mode`. Exits with an error message if
//    `filename != nullptr` and the named file cannot be opened.

io61_file *io61_open_check(const char *filename, int mode)
{
    int fd;
    if (filename)
    {
        fd = open(filename, mode, 0666);
    }
    else if ((mode & O_ACCMODE) == O_RDONLY)
    {
        fd = STDIN_FILENO;
    }
    else
    {
        fd = STDOUT_FILENO;
    }
    if (fd < 0)
    {
        fprintf(stderr, "%s: %s\n", filename, strerror(errno));
        exit(1);
    }
    return io61_fdopen(fd, mode & O_ACCMODE);
}

// io61_fileno(f)
//    Returns the file descriptor associated with `f`.

int io61_fileno(io61_file *f)
{
    return f->fd;
}

// io61_filesize(f)
//    Returns the size of `f` in bytes. Returns -1 if `f` does not have a
//    well-defined size (for instance, if it is a pipe).

off_t io61_filesize(io61_file *f)
{
    struct stat s;
    int r = fstat(f->fd, &s);
    if (r >= 0 && S_ISREG(s.st_mode))
    {
        return s.st_size;
    }
    else
    {
        return -1;
    }
}
