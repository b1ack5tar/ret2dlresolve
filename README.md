# ret2dlresolve
ret2dlresolve的学习笔记，复现时最好自己进行动态调试感受动态链接的过程
### 编译命令：
x86：gcc -o pwn ./pwn.c -m32 -no-pie -fno-stack-protector<br>
x64：gcc -o pwn ./pwn.c -no-pie -fno-stack-protector -z norelro -masm=intel<br>
### 致谢
https://ltfa1l.top/2024/06/05/system/StackOverflow/ret2dlresolve/
