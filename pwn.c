#include<stdio.h>

void vuln() {
    char content[0x100];
    read(0, content, 0x200);
}

int main() {
    vuln();
    return 0;
}