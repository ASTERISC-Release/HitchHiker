#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#define FIFO_PATH "/tmp/my_fifo"
#define MAX_BUFFER 1024
#define BUF_SIZE 1024

int main(int argc, char *argv[]) {
    char buf0[] = "hello from hhkrd..\n";
    write(1, buf0, sizeof(buf0));
    
    char buffer[MAX_BUFFER];
    int fd = open(FIFO_PATH, O_RDONLY);
    
    // 从 FIFO 中读取数据
    char buf[BUF_SIZE];
    while (1) {
        ssize_t len = read(fd, buf, BUF_SIZE - 1);
        if (len <= 0) {
            break;
        }
        buf[len] = '\0';
        printf("Received: %s\n", buf);
    }
    
    close(fd);
    return 0;
}