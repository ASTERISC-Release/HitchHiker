//"""
// A test case for SATA's record-and-replay.  
//"""

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/syscall.h>

#define SZ_4KB      (1 << 12)
#define SZ_1MB      (1 << 20)
#define SZ_8MB      (SZ_1MB) * 8

#define BLOCK_SIZE  (SZ_4KB) / 4
// #define BLOCK_SIZE  SZ_4KB


int devfd = -1;
static int open_tl_intf() {
    if ((devfd = open("/dev/hitchhiker-ctl", O_RDONLY)) < 0) {
        perror("open");
        return -1;
    }
    return 0;
}
static int close_tl_intf() {
    if (devfd > 0 && close(devfd) < 0) {
        perror("close");
        return -1;
    }
    devfd = -1;
    return 0;
}

static int enable_record_debug() {
    if (devfd < 0 && open_tl_intf() < 0) {
        return -1;
    }
    int r = ioctl(devfd, 0, 1);
    if (r < 0) {
        perror("ioctl");
        return -1;
    }
    return 0;
}
static int disable_record_debug() {
    if (devfd < 0 && open_tl_intf() < 0) {
        return -1;
    }
    int r = ioctl(devfd, 0, 0);
    if (r < 0) {
        perror("ioctl");
        return -1;
    }
    return 0;
}

int main() {
    int pid = getpid();
    printf("sata-test: self pid = %d.\n", pid);
    // --------------------------------------------------------------
    /* ENABLE record debug */
    if (enable_record_debug() < 0) {
        return -1;
    }
    int fd = open("/dev/sda", O_RDWR | O_DIRECT | O_SYNC, 0);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    // /* DISABLE record debug */
    // if (disable_record_debug() < 0) {
    //     return -1;
    // }
    // ---------------------------------------------------------------
    // allocate memory aligned to 512 bytes
    char *buf; 
    if(posix_memalign((void **)&buf, BLOCK_SIZE, BLOCK_SIZE) != 0) {
        perror("posix_memalign");
        return -1;
    }
    printf("buf addr: 0x%lx.\n", (unsigned long)buf);
    // fill buf
    memset(buf, 'A', BLOCK_SIZE - 1);
    buf[BLOCK_SIZE - 1] = '\0';
    // write 
    printf("<<<\n");

    int ret = syscall(SYS_write, fd, buf, BLOCK_SIZE);
    if (ret < 0) {
        perror("write");
        return -1;
    } else {
        printf("write %d bytes.\n", ret);
    }
    
    // // write again
    // memset(buf, 'B', BLOCK_SIZE - 1);
    // ret = syscall(SYS_write, fd, buf, BLOCK_SIZE);

    /* DISABLE record debug */
    if (disable_record_debug() < 0) {
        return -1;
    }
    printf(">>>\n");

    // if (ret < 0) {
    //     perror("write");
    //     return -1;
    // } else {
    //     printf("write %d bytes.\n", ret);
    // }
    // printf("write: %s.\n", buf);
    printf("|||\n");
    
    enable_record_debug();
    close(fd);
    disable_record_debug();
    // close debug
    close_tl_intf();
    return 0;
}