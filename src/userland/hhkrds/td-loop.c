#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arch_def.h>

#define DEV_PATH		"/dev/hitchhiker-ctl"

void sig_handler(int signum) {
    char buf[100];
    sprintf(buf, "\ncatch the signal: %d.\n", signum);
    write(STDERR_FILENO, buf, strlen(buf));   
}

int main(int argc, char *argv[]) {
    printf("hello from trustd-loop...\n");
    

    int fd = open(DEV_PATH, O_RDWR, 0);
    // do mmap
    ioctl(fd, HHKR_MMAP_BUF, 0);

    for (unsigned int i = 0; ; i++) {
    }
    
    return 0;
}