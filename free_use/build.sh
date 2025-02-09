#!/bin/sh
arm-linux-gnueabi-gcc -c container.c -o container.o -march=armv7-a -mfpu=neon -mfloat-abi=hard -ffreestanding -nostdlib -Wall -O2

# 定义工具链前缀
TOOLCHAIN_PREFIX="arm-linux-gnueabi-"

# 编译C代码
${TOOLCHAIN_PREFIX}gcc -c container.c -o container.o -march=armv7-a -mfpu=neon -mfloat-abi=hard -ffreestanding -nostdlib -Wall -O2

# 编译汇编启动代码
${TOOLCHAIN_PREFIX}gcc -c start.S -o start.o -march=armv7-a -mfpu=neon -mfloat-abi=hard -ffreestanding -nostdlib -Wall -O2

# 链接目标文件
${TOOLCHAIN_PREFIX}gcc -T linker.ld -o simulator.elf start.o container.o -march=armv7-a -mfpu=neon -mfloat-abi=hard -ffreestanding -nostdlib -Wall -O2

# 生成二进制文件
${TOOLCHAIN_PREFIX}objcopy -O binary simulator.elf simulator.bin

echo "Build successful. Output binary: simulator.bin"