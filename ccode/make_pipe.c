#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int pipefd[2];
    char buffer[10];

    // pipe creation
    if (pipe(pipefd) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    printf("pipefd[0]: %d\n", pipefd[0]);

    // write data
    write(pipefd[1], "hello", 5);

    // read data
    read(pipefd[0], buffer, 5);
    buffer[5] = '\0'; // NULL 문자를 추가
    printf("Read from pipe: %s\n", buffer);

    // close pipe
    close(pipefd[0]);
    close(pipefd[1]);

    return 0;
}

