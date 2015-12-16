#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void callsystem()
{
    system("/system/bin/sh");
}
 
 
void vulnerable_function() {
    char buf[128];
    read(STDIN_FILENO, buf, 256);
}
 
int main(int argc, char** argv) {
    if (argc==2&&strcmp("passwd",argv[1])==0)
        callsystem();
    write(STDOUT_FILENO, "Hello, World\n", 13);    
    vulnerable_function();
}

