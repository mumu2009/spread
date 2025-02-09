#!/bin/sh

# 检查是否已安装pkg
if ! command -v pkg > /dev/null 2>&1; then
    echo "pkg not found. Please install pkg first."
    exit 1
fi

# 使用pkg安装GCC
pkg install -y gcc

# 定义源文件和目标可执行文件
source_file="d:/programme/spread(powerd_by_C)/core/container/container.c"
output_file="d:/programme/spread(powerd_by_C)/core/container/simulator"

# 编译代码
gcc -o $output_file $source_file -Wall -Wextra -std=c99 -O2 -lsocket -lpthread

# 检查编译结果
if [ $? -eq 0 ]; then
    echo "Compilation successful. Executable created at $output_file"
else
    echo "Compilation failed."
fi