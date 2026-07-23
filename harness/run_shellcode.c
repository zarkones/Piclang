/*
 * run_shellcode.c - map a PIC blob RWX and call offset 0.
 *
 * Build:  cc -O2 -o run_shellcode run_shellcode.c
 * Usage:  ./run_shellcode ../examples/hello.bin
 *
 * The shellcode uses the Microsoft x64 calling convention for calls.
 * On Linux this harness still works for pure computation (no Win32 APIs).
 * Return value is printed as unsigned long.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

typedef unsigned long (*shell_entry_t)(void);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        return 2;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return 1;
    }
    size_t n = (size_t)st.st_size;
    if (n == 0) {
        fprintf(stderr, "empty file\n");
        return 1;
    }
    /* page-align mapping size */
    size_t map_sz = (n + 0xFFF) & ~((size_t)0xFFF);
    void *mem = mmap(NULL, map_sz, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    ssize_t rd = read(fd, mem, n);
    close(fd);
    if (rd < 0 || (size_t)rd != n) {
        perror("read");
        return 1;
    }
    /* clear leftover if any */
    if ((size_t)rd < map_sz) {
        memset((char *)mem + rd, 0, map_sz - (size_t)rd);
    }

    printf("[*] mapped %zu bytes RWX at %p\n", n, mem);
    printf("[*] entry  = %p\n", mem);
    shell_entry_t entry = (shell_entry_t)mem;
    unsigned long ret = entry();
    printf("[+] return = %lu (0x%lx)\n", ret, ret);
    munmap(mem, map_sz);
    return 0;
}
