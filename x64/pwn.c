#include <stdio.h>

asm("pop rdx; ret;"
    "pop rsi; pop r15; ret;"
    "pop rdi; ret"
);

int main(){
    char content[0x100];
    read(0, content, 0x300);
    return 0;
}