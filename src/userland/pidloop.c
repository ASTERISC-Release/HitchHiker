#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#define __NR_getpid 172

#define BOUND_NUM   1000000      // 1 million syscalls

int main() {
    for (int i = 0; i < BOUND_NUM; i++) {
        int pid;
        pid = syscall(__NR_getpid);
    }

    return 0;
}