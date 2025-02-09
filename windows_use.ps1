# build.ps1

# 检查是否已安装Chocolatey
if (-Not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Chocolatey not found. Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# 使用Chocolatey安装MinGW
choco install mingw -y

# 添加MinGW到系统路径
$env:Path += ";C:\Program Files\mingw-w64\x86_64-8.1.0-posix-seh-rt_v6-rev0\mingw64\bin"

# 定义源文件和目标可执行文件
$sourceFile = "d:\programme\spread(powerd_by_C)\core\container\container.c"
$outputFile = "d:\programme\spread(powerd_by_C)\core\container\simulator.exe"

# 编译代码
gcc -o $outputFile $sourceFile -Wall -Wextra -std=c99 -O2 -lws2_32

# 检查编译结果
if ($LASTEXITCODE -eq 0) {
    Write-Host "Compilation successful. Executable created at $outputFile"
} else {
    Write-Host "Compilation failed."
}