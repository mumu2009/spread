    .section .text
    .global _start

_start:
    // 初始化硬件
    // 例如，设置堆栈指针
    ldr sp, =stack_top

    // 跳转到main函数
    bl main

    // 无限循环
1:  b 1b

    .section .bss
    .align 4
stack_bottom:
    .space 4096
stack_top: