#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <sys/wait.h>
int is_valid_path(const char *path);
// 网络配置函数声明
void create_network_namespace(const char *ns_name);
void create_veth_pair(const char *veth1, const char *veth2);
void move_veth_to_namespace(const char *veth, const char *ns_name);
void configure_veth_in_namespace(const char *ns_name, const char *veth, const char *ip);
void create_bridge(const char *bridge_name);
void add_veth_to_bridge(const char *veth, const char *bridge_name);
void configure_nat();

// 安全模块函数声明
int is_running_in_vm();
void setup_seccomp(int is_vm);
void drop_privileges(int is_vm);
#define MEMORY_SIZE 10000
#define MAX_MACRO_NAME_LENGTH 100
#define MAX_COMMAND_LENGTH 1024
#define MAX_LABELS 100
#define MAX_FILES 100
#define MAX_DIRECTORIES 100
#define MAX_NETWORK_BUFFER_SIZE 1024
char *read_c_code_from_file(const char *filename);
#include <seccomp.h>
typedef enum {
    AST_VARIABLE,
    AST_NUMBER,
    AST_BINARY_OP,
    AST_ASSIGN,
    AST_IF,
    AST_FUNCTION,  // 添加这一行
    AST_RETURN,    // 添加这一行
    AST_STRUCT,    // 添加这一行
    AST_ARRAY,     // 添加这一行
    AST_POINTER    // 添加这一行
} ASTNodeType;

typedef struct ASTNode {
    ASTNodeType type;
    char value[MAX_COMMAND_LENGTH];
    struct ASTNode *left;
    struct ASTNode *right;
    struct ASTNode *body;      // 添加这一行
    struct ASTNode *fields;    // 添加这一行
    struct ASTNode *elements;  // 添加这一行
    struct ASTNode *pointee;   // 添加这一行
} ASTNode;
void setup_seccomp(int is_vm)
{
    scmp_filter_ctx ctx;

    // 初始化 seccomp 上下文
    ctx = seccomp_init(SCMP_ACT_KILL); // 默认情况下，禁止所有系统调用

    if (ctx == NULL)
    {
        perror("seccomp_init failed");
        exit(EXIT_FAILURE);
    }

    // 允许基本的系统调用
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);

    // 如果是虚拟机，进一步限制系统调用
    if (is_vm)
    {
        // 禁止某些危险的系统调用
        seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0);
        seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_load), 0);
        seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(reboot), 0);
        seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(openat), 0);
    }

    // 应用 seccomp 过滤器
    if (seccomp_load(ctx) < 0)
    {
        perror("seccomp_load failed");
        exit(EXIT_FAILURE);
    }

    // 释放 seccomp 上下文
    seccomp_release(ctx);
}
#include <unistd.h>

void drop_privileges(int is_vm)
{
    if (is_vm)
    {
        // 在虚拟机中运行时，降低权限
        if (setuid(getuid()) != 0)
        {
            perror("setuid failed");
            exit(EXIT_FAILURE);
        }
        if (setgid(getgid()) != 0)
        {
            perror("setgid failed");
            exit(EXIT_FAILURE);
        }
    }
}
#include <stdio.h>
#include <string.h>

int is_running_in_vm()
{
    FILE *cpuinfo = fopen("/proc/cpuinfo", "r");
    if (cpuinfo == NULL)
    {
        perror("Failed to open /proc/cpuinfo");
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), cpuinfo))
    {
        if (strstr(line, "hypervisor") != NULL)
        {
            fclose(cpuinfo);
            return 1; // 在虚拟机中运行
        }
    }

    fclose(cpuinfo);
    return 0; // 不在虚拟机中运行
}
// ALU 单元结构体
typedef struct
{
    int input1;
    int input2;
    int mode;
} ALU_unit;

// 内存结构体
typedef struct
{
    int memory_array[MEMORY_SIZE]; // 内存数组
    int *pointers[MEMORY_SIZE];    // 指针数组
    int pointer_count;             // 当前指针数量
} Memory;
// 标签结构体
typedef struct
{
    char name[MAX_COMMAND_LENGTH];
    long position; // 标签在文件中的位置
} Label;

// 文件结构体
typedef struct
{
    char name[MAX_COMMAND_LENGTH];
    char content[MAX_COMMAND_LENGTH];
} File;

// 目录结构体
typedef struct
{
    char name[MAX_COMMAND_LENGTH];
    File files[MAX_FILES];
    int file_count;
} Directory;

#define MAX_MOUNT_POINTS 10

typedef struct
{
    char mount_path[MAX_COMMAND_LENGTH];    // 挂载路径
    char external_path[MAX_COMMAND_LENGTH]; // 外部介质路径
} MountPoint;

typedef struct
{
    Directory directories[MAX_DIRECTORIES];
    int directory_count;
    char current_directory[MAX_COMMAND_LENGTH];
    MountPoint mount_points[MAX_MOUNT_POINTS]; // 挂载点数组
    int mount_point_count;                     // 当前挂载点数量
} FileSystem;
// 增加对函数的支持
typedef struct
{
    char name[MAX_COMMAND_LENGTH];
    ASTNode *body;
} Function;

Function functions[MAX_MACRO_NAME_LENGTH];
int function_count = 0;

// 查找函数
Function *find_function(const char *name)
{
    for (int i = 0; i < function_count; i++)
    {
        if (strcmp(functions[i].name, name) == 0)
        {
            return &functions[i];
        }
    }
    return NULL;
}

// 增加对结构体的支持
typedef struct
{
    char name[MAX_COMMAND_LENGTH];
    ASTNode *fields;
} StructType;

StructType struct_types[MAX_MACRO_NAME_LENGTH];
int struct_type_count = 0;

// 查找结构体
StructType *find_struct_type(const char *name)
{
    for (int i = 0; i < struct_type_count; i++)
    {
        if (strcmp(struct_types[i].name, name) == 0)
        {
            return &struct_types[i];
        }
    }
    return NULL;
}

// 增加对数组的支持
typedef struct
{
    char name[MAX_COMMAND_LENGTH];
    int size;
    ASTNode *elements;
} ArrayType;

ArrayType array_types[MAX_MACRO_NAME_LENGTH];
int array_type_count = 0;

// 查找数组
ArrayType *find_array_type(const char *name)
{
    for (int i = 0; i < array_type_count; i++)
    {
        if (strcmp(array_types[i].name, name) == 0)
        {
            return &array_types[i];
        }
    }
    return NULL;
}

// 增加对指针的支持
typedef struct
{
    char name[MAX_COMMAND_LENGTH];
    ASTNode *pointee;
} PointerType;

PointerType pointer_types[MAX_MACRO_NAME_LENGTH];
int pointer_type_count = 0;

// 查找指针
PointerType *find_pointer_type(const char *name)
{
    for (int i = 0; i < pointer_type_count; i++)
    {
        if (strcmp(pointer_types[i].name, name) == 0)
        {
            return &pointer_types[i];
        }
    }
    return NULL;
}
FileSystem fs = {0}; // 全局文件系统
// 挂载外部介质
// 挂载外部存储
int mount_external(const char *mount_path, const char *external_path)
{
    if (fs.mount_point_count >= MAX_MOUNT_POINTS)
    {
        printf("Error: Maximum number of mount points reached\n");
        return -1;
    }

    // 检查挂载路径是否已经存在
    for (int i = 0; i < fs.mount_point_count; i++)
    {
        if (strcmp(fs.mount_points[i].mount_path, mount_path) == 0)
        {
            printf("Error: Mount path '%s' already in use\n", mount_path);
            return -1;
        }
    }

    // 添加挂载点
    strcpy(fs.mount_points[fs.mount_point_count].mount_path, mount_path);
    strcpy(fs.mount_points[fs.mount_point_count].external_path, external_path);
    fs.mount_point_count++;

    printf("External media mounted at '%s'\n", mount_path);
    return 0;
}
// 卸载外部介质

int unmount_external(const char *mount_path)
{
    for (int i = 0; i < fs.mount_point_count; i++)
    {
        if (strcmp(fs.mount_points[i].mount_path, mount_path) == 0)
        {
            // 移除挂载点
            for (int j = i; j < fs.mount_point_count - 1; j++)
            {
                fs.mount_points[j] = fs.mount_points[j + 1];
            }
            fs.mount_point_count--;
            printf("External media unmounted from '%s'\n", mount_path);
            return 0;
        }
    }

    printf("Error: Mount path '%s' not found\n", mount_path);
    return -1;
}
// 创建指针
int *create_pointer(int address, Memory *memory)
{
    if (memory->pointer_count >= MEMORY_SIZE)
    {
        printf("Error: Maximum number of pointers reached\n");
        return NULL;
    }
    memory->pointers[memory->pointer_count] = &memory->memory_array[address];
    memory->pointer_count++;
    return memory->pointers[memory->pointer_count - 1];
}

// 解引用指针
int dereference_pointer(int *pointer)
{
    return *pointer;
}

// 指针加法
int *pointer_add(int *pointer, int offset)
{
    return pointer + offset;
}

// 指针减法
int *pointer_sub(int *pointer, int offset)
{
    return pointer - offset;
}
// 计算函数
int compute(ALU_unit alu_unit)
{
    switch (alu_unit.mode)
    {
    case 0:
        return alu_unit.input1 + alu_unit.input2; // 加法
    case 1:
        return alu_unit.input1 - alu_unit.input2; // 减法
    case 2:
        return alu_unit.input1 * alu_unit.input2; // 乘法
    case 3:
        if (alu_unit.input2 == 0)
        {
            printf("Error: Division by zero\n");
            return 0;
        }
        return alu_unit.input1 / alu_unit.input2; // 除法
    case 4:
        return alu_unit.input1 % alu_unit.input2; // 取模
    case 5:
        return alu_unit.input1 & alu_unit.input2; // 按位与
    case 6:
        return alu_unit.input1 | alu_unit.input2; // 按位或
    case 7:
        return alu_unit.input1 ^ alu_unit.input2; // 按位异或
    case 8:
        if (alu_unit.input1 == alu_unit.input2)
            return 0;
        else if (alu_unit.input1 > alu_unit.input2)
            return 1;
        else
            return -1; // 比较
    default:
        printf("Error: Invalid mode\n");
        return 0;
    }
}

// 内存读写函数
int memory_use(int write_or_read, int address, int data, Memory *memory)
{
    if (address < 0 || address >= MEMORY_SIZE)
    {
        printf("Error: Invalid address\n");
        return 0;
    }

    if (write_or_read == 0)
    { // 写操作
        memory->memory_array[address] = data;
        return data;
    }
    else if (write_or_read == 1)
    { // 读操作
        return memory->memory_array[address];
    }
    else
    {
        printf("Error: Invalid operation\n");
        return 0;
    }
}

// 解析输入：如果输入的第一位是 '0'，则从内存中读取数据；否则，直接使用输入值
// 修改 parse_input 函数以支持指针
int parse_input(const char *input_str, Memory *memory)
{
    if (input_str[0] == '0' && strlen(input_str) > 1)
    {
        // 内存地址
        int address = atoi(input_str + 1);
        return memory_use(1, address, 0, memory);
    }
    else if (input_str[0] == '&')
    {
        // 指针地址
        int address = atoi(input_str + 1);
        return (intptr_t)create_pointer(address, memory);
    }
    else if (isdigit(input_str[0]))
    {
        // 直接使用整数
        return atoi(input_str);
    }
    else
    {
        // 字符串输入，哈希为整数
        unsigned long hash = 5381;
        int c;
        const char *str = input_str;
        while ((c = *str++))
        {
            hash = ((hash << 5) + hash) + c; // hash * 33 + c
        }
        return (intptr_t)(hash % MEMORY_SIZE); // 确保哈希值在内存范围内
    }
}

// 查找目录
Directory *find_directory(const char *dirname)
{
    for (int i = 0; i < fs.directory_count; i++)
    {
        if (strcmp(fs.directories[i].name, dirname) == 0)
        {
            return &fs.directories[i];
        }
    }
    return NULL;
}

// 查找文件
File *find_file(Directory *dir, const char *filename)
{
    for (int i = 0; i < dir->file_count; i++)
    {
        if (strcmp(dir->files[i].name, filename) == 0)
        {
            return &dir->files[i];
        }
    }
    return NULL;
}

// 创建目录
int create_directory(const char *dirname)
{
    if (!is_valid_path(dirname))
    {
        printf("Error: Invalid directory path\n");
        return -1;
    }

    if (fs.directory_count >= MAX_DIRECTORIES)
    {
        printf("Error: Directory limit reached\n");
        return -1;
    }

    Directory *dir = find_directory(dirname);
    if (dir != NULL)
    {
        printf("Directory '%s' already exists, skipping creation.\n", dirname);
        return 0; // 目录已存在，跳过创建
    }

    strcpy(fs.directories[fs.directory_count].name, dirname);
    fs.directories[fs.directory_count].file_count = 0;
    fs.directory_count++;
    printf("Directory '%s' created successfully.\n", dirname);
    return 0;
}

int create_file(const char *filename)
{
    if (!is_valid_path(filename))
    {
        printf("Error: Invalid file path\n");
        return -1;
    }

    Directory *current_dir = find_directory(fs.current_directory);
    if (current_dir == NULL)
    {
        printf("Error: Current directory not found\n");
        return -1;
    }

    if (current_dir->file_count >= MAX_FILES)
    {
        printf("Error: File limit reached in directory '%s'\n", fs.current_directory);
        return -1;
    }

    File *file = find_file(current_dir, filename);
    if (file != NULL)
    {
        printf("File '%s' already exists, skipping creation.\n", filename);
        return 0; // 文件已存在，跳过创建
    }

    strcpy(current_dir->files[current_dir->file_count].name, filename);
    current_dir->files[current_dir->file_count].content[0] = '\0';
    current_dir->file_count++;
    printf("File '%s' created successfully.\n", filename);
    return 0;
}
// 查找文件（支持挂载点）
File *find_file_with_mount(const char *path)
{
    // 检查路径是否在挂载点中
    for (int i = 0; i < fs.mount_point_count; i++)
    {
        if (strncmp(path, fs.mount_points[i].mount_path, strlen(fs.mount_points[i].mount_path)) == 0)
        {
            // 路径在挂载点中，操作外部介质
            char external_path[MAX_COMMAND_LENGTH];
            snprintf(external_path, sizeof(external_path), "%s%s", fs.mount_points[i].external_path, path + strlen(fs.mount_points[i].mount_path));

            // 这里需要实现对外部介质的文件操作
            // 例如，可以使用系统调用来操作外部文件
            // 由于外部介质的文件系统可能不同，这里只是一个示例
            FILE *file = fopen(external_path, "r");
            if (file)
            {
                fclose(file);
                // 返回一个虚拟的 File 结构体
                static File virtual_file;
                strcpy(virtual_file.name, path);
                strcpy(virtual_file.content, "External file content");
                return &virtual_file;
            }
            else
            {
                return NULL;
            }
        }
    }

    // 路径不在挂载点中，操作本地文件系统
    Directory *current_dir = find_directory(fs.current_directory);
    if (current_dir == NULL)
    {
        return NULL;
    }

    return find_file(current_dir, path);
}
// 改变当前目录
int change_directory(const char *dirname)
{
    Directory *dir = find_directory(dirname);
    if (dir == NULL)
    {
        printf("Error: Directory '%s' not found\n", dirname);
        return -1;
    }

    strcpy(fs.current_directory, dirname);
    printf("Changed directory to '%s'\n", dirname);
    return 0;
}

// 打印文件内容
int print_file(const char *filename)
{
    Directory *current_dir = find_directory(fs.current_directory);
    if (current_dir == NULL)
    {
        printf("Error: Current directory not found\n");
        return -1;
    }

    File *file = find_file(current_dir, filename);
    if (file == NULL)
    {
        printf("Error: File '%s' not found\n", filename);
        return -1;
    }

    printf("%s\n", file->content);
    return 0;
}

// 删除文件
int delete_file(const char *filename)
{
    Directory *current_dir = find_directory(fs.current_directory);
    if (current_dir == NULL)
    {
        printf("Error: Current directory not found\n");
        return -1;
    }

    for (int i = 0; i < current_dir->file_count; i++)
    {
        if (strcmp(current_dir->files[i].name, filename) == 0)
        {
            for (int j = i; j < current_dir->file_count - 1; j++)
            {
                current_dir->files[j] = current_dir->files[j + 1];
            }
            current_dir->file_count--;
            printf("File '%s' deleted successfully.\n", filename);
            return 0;
        }
    }

    printf("Error: File '%s' not found\n", filename);
    return -1;
}

// 列出目录内容
int list_directory(const char *dirname)
{
    Directory *dir = find_directory(dirname);
    if (dir == NULL)
    {
        printf("Error: Directory '%s' not found\n", dirname);
        return -1;
    }

    printf("Contents of directory '%s':\n", dirname);
    for (int i = 0; i < dir->file_count; i++)
    {
        printf("%s\n", dir->files[i].name);
    }
    return 0;
}

// 发送数据到远程服务器
int send_data_to_server(const char *server_ip, int port, const char *data)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        printf("Error: Failed to create socket\n");
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        printf("Error: Invalid address or address not supported\n");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("Error: Connection failed\n");
        close(sock);
        return -1;
    }

    if (send(sock, data, strlen(data), 0) < 0)
    {
        printf("Error: Failed to send data\n");
        close(sock);
        return -1;
    }

    printf("Data sent to server %s:%d: %s\n", server_ip, port, data);
    close(sock);
    return 0;
}

// 从远程服务器接收数据
int receive_data_from_server(const char *server_ip, int port, char *buffer, int buffer_size)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        printf("Error: Failed to create socket\n");
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        printf("Error: Invalid address or address not supported\n");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("Error: Connection failed\n");
        close(sock);
        return -1;
    }

    int bytes_received = recv(sock, buffer, buffer_size - 1, 0);
    if (bytes_received < 0)
    {
        printf("Error: Failed to receive data\n");
        close(sock);
        return -1;
    }

    buffer[bytes_received] = '\0'; // 确保字符串以 null 结尾
    printf("Data received from server %s:%d: %s\n", server_ip, port, buffer);
    close(sock);
    return bytes_received;
}

// 处理命令的函数
void process_command(char command, const char *first_input_str, const char *second_input_str, int output_place, Memory *memory)
{
    ALU_unit alu_unit;
    int result;
    int first_input = parse_input(first_input_str, memory);
    int second_input = parse_input(second_input_str, memory);

    switch (command)
    {
    case '+':
        alu_unit = (ALU_unit){first_input, second_input, 0};
        break;
    case '-':
        alu_unit = (ALU_unit){first_input, second_input, 1};
        break;
    case 'x':
        alu_unit = (ALU_unit){first_input, second_input, 2};
        break;
    case '/':
        alu_unit = (ALU_unit){first_input, second_input, 3};
        break;
    case '%':
        alu_unit = (ALU_unit){first_input, second_input, 4};
        break;
    case 'y':
        alu_unit = (ALU_unit){first_input, second_input, 5};
        break;
    case '|':
        alu_unit = (ALU_unit){first_input, second_input, 6};
        break;
    case '^':
        alu_unit = (ALU_unit){first_input, second_input, 7};
        break;
    case '=':
        alu_unit = (ALU_unit){first_input, second_input, 8};
        break;
    case 'r':
    { // 读取文件
        Directory *current_dir = find_directory(fs.current_directory);
        if (current_dir == NULL)
        {
            printf("Error: Current directory not found\n");
            return;
        }

        File *file = find_file(current_dir, first_input_str);
        if (file == NULL)
        {
            printf("Error: File '%s' not found\n", first_input_str);
            return;
        }

        int data = atoi(file->content);
        memory_use(0, output_place, data, memory);
        printf("Data read from file '%s' and stored at address %d: %s\n", first_input_str, output_place, file->content);
        return;
    }
    case 'w':
    { // 写入文件
        Directory *current_dir = find_directory(fs.current_directory);
        if (current_dir == NULL)
        {
            printf("Error: Current directory not found\n");
            return;
        }

        File *file = find_file(current_dir, first_input_str);
        if (file == NULL)
        {
            printf("Error: File '%s' not found\n", first_input_str);
            return;
        }

        sprintf(file->content, "%d", second_input);
        printf("Data written to file '%s': %s\n", first_input_str, file->content);
        return;
    }
    case 'm':
    { // mkdir
        create_directory(first_input_str);
        return;
    }
    case 't':
    { // touch
        create_file(first_input_str);
        return;
    }
    case 'c':
    { // cd
        change_directory(first_input_str);
        return;
    }
    case 'p':
    { // print file (cat)
        print_file(first_input_str);
        return;
    }
    case 'd':
    { // delete file (rm)
        delete_file(first_input_str);
        return;
    }
    case 'l':
    { // list directory (ls)
        list_directory(first_input_str);
        return;
    }
    case 's':
    { // 发送数据到服务器
        char server_ip[MAX_COMMAND_LENGTH];
        int port = first_input;
        char data[MAX_COMMAND_LENGTH];
        sprintf(data, "%d", second_input);
        sprintf(server_ip, "%d.%d.%d.%d", (output_place >> 24) & 0xFF, (output_place >> 16) & 0xFF, (output_place >> 8) & 0xFF, output_place & 0xFF);
        send_data_to_server(server_ip, port, data);
        return;
    }
    case 'g':
    { // 从服务器接收数据
        char server_ip[MAX_COMMAND_LENGTH];
        int port = first_input;
        char buffer[MAX_NETWORK_BUFFER_SIZE];
        sprintf(server_ip, "%d.%d.%d.%d", (output_place >> 24) & 0xFF, (output_place >> 16) & 0xFF, (output_place >> 8) & 0xFF, output_place & 0xFF);
        int bytes_received = receive_data_from_server(server_ip, port, buffer, sizeof(buffer));
        if (bytes_received > 0)
        {
            memory_use(0, second_input, atoi(buffer), memory);
            printf("Data received from server and stored at address %d: %s\n", second_input, buffer);
        }
        return;
    }
    case '&':
        // 获取变量的地址
        result = (intptr_t)create_pointer(first_input, memory);
        memory_use(0, output_place, result, memory);
        printf("Pointer created and stored at address %d: %p\n", output_place, (void *)(intptr_t)result);
        return;
    case '*':
        // 解引用指针
        result = dereference_pointer((int *)(intptr_t)first_input);
        memory_use(0, output_place, result, memory);
        printf("Pointer dereferenced and stored at address %d: %d\n", output_place, result);
        return;
    case 'a': // 指针加法
        result = (intptr_t)pointer_add((int *)(intptr_t)first_input, second_input);
        memory_use(0, output_place, result, memory);
        printf("Pointer addition result stored at address %d: %p\n", output_place, (void *)(intptr_t)result);
        return;
    case 'b': // 指针减法
        result = (intptr_t)pointer_sub((int *)(intptr_t)first_input, second_input);
        memory_use(0, output_place, result, memory);
        printf("Pointer subtraction result stored at address %d: %p\n", output_place, (void *)(intptr_t)result);
        return;

    default:
        printf("Error: Invalid command\n");
        return;
    }

    result = compute(alu_unit);
    memory_use(0, output_place, result, memory);
    printf("Result stored at address %d: %d\n", output_place, result);
}
// 定义宏
void define_macro(char *macro_name)
{
    char filename[MAX_MACRO_NAME_LENGTH + 10];
    sprintf(filename, "./%s.txt", macro_name);

    FILE *file = fopen(filename, "w");
    if (file == NULL)
    {
        printf("Error: Failed to create macro file\n");
        return;
    }

    printf("Enter macro content (type 'end' to finish):\n");
    char line[MAX_COMMAND_LENGTH];
    while (1)
    {
        fgets(line, MAX_COMMAND_LENGTH, stdin);
        if (strcmp(line, "end\n") == 0)
        {
            break;
        }
        fprintf(file, "%s", line);
    }

    fclose(file);
    printf("Macro '%s' defined successfully.\n", macro_name);
}

// 查找标签的位置
long find_label_position(FILE *file, Label *labels, int label_count, char *label_name)
{
    for (int i = 0; i < label_count; i++)
    {
        if (strcmp(labels[i].name, label_name) == 0)
        {
            return labels[i].position;
        }
    }
    return -1; // 标签未找到
}

// 执行宏
// 参数替换函数
void replace_params(char *line, char param_values[MAX_MACRO_NAME_LENGTH][MAX_COMMAND_LENGTH], int argc)
{
    char new_line[MAX_COMMAND_LENGTH] = {0};
    char *pos = line;
    while (*pos)
    {
        if (*pos == '$' && isdigit(*(pos + 1)))
        {
            int index = atoi(pos + 1) - 1; // $1对应索引0
            if (index >= 0 && index < argc)
            {
                strcat(new_line, param_values[index]);
            }
            else
            {
                strcat(new_line, "0");
            }
            pos += 2; // 跳过$和数字
        }
        else
        {
            char temp[2] = {*pos, '\0'};
            strcat(new_line, temp);
            pos++;
        }
    }
    strcpy(line, new_line);
}
// 验证路径是否合法
int is_valid_path(const char *path)
{
    // 确保路径不以 '/' 开头，防止访问系统根目录
    if (path[0] == '/')
    {
        return 0;
    }

    // 确保路径不包含 ".."，防止路径遍历
    if (strstr(path, "..") != NULL)
    {
        return 0;
    }

    return 1;
}
// 执行宏
void execute_macro(char *macro_name, Memory *memory, int argc, char *argv[])
{
    char filename[MAX_MACRO_NAME_LENGTH + 10];
    sprintf(filename, "./%s.txt", macro_name);

    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("Error: Macro '%s' not found\n", macro_name);
        return;
    }

    // 读取参数
    char params[MAX_COMMAND_LENGTH];
    fgets(params, MAX_COMMAND_LENGTH, file);
    if (strncmp(params, "params", 6) == 0)
    {
        // 解析参数名并映射到实际值
        char param_values[MAX_MACRO_NAME_LENGTH][MAX_COMMAND_LENGTH];
        char *token = strtok(params + 7, " \n");
        int param_count = 0;
        while (token != NULL && param_count < MAX_MACRO_NAME_LENGTH)
        {
            // 将参数名映射到传入的值（$1对应argv[0], $2对应argv[1]...）
            if (param_count < argc)
            {
                strcpy(param_values[param_count], argv[param_count]);
            }
            else
            {
                strcpy(param_values[param_count], "0"); // 默认值
            }
            param_count++;
            token = strtok(NULL, " \n");
        }

        Label labels[MAX_LABELS];
        int label_count = 0;

        // 第一次扫描：记录所有标签的位置
        char line[MAX_COMMAND_LENGTH];
        long position = ftell(file);
        while (fgets(line, MAX_COMMAND_LENGTH, file))
        {
            if (line[strlen(line) - 1] == '\n')
            {
                line[strlen(line) - 1] = '\0'; // 去掉换行符
            }

            if (strstr(line, ":") != NULL)
            { // 找到标签
                strcpy(labels[label_count].name, line);
                labels[label_count].position = position;
                label_count++;
            }
            position = ftell(file);
        }

        // 第二次扫描：执行命令（添加参数替换）
        fseek(file, 0, SEEK_SET);
        int if_condition = 1; // 1 表示条件为真，0 表示条件为假
        while (fgets(line, MAX_COMMAND_LENGTH, file))
        {
            if (line[strlen(line) - 1] == '\n')
            {
                line[strlen(line) - 1] = '\0'; // 去掉换行符
            }

            if (strstr(line, ":") != NULL)
            { // 跳过标签行
                continue;
            }

            // 替换参数占位符
            replace_params(line, param_values, argc);

            if (strncmp(line, "if", 2) == 0)
            { // 处理 if 语句
                int condition_value;
                sscanf(line, "if %d", &condition_value);
                if_condition = (condition_value != 0);
                continue;
            }

            if (strncmp(line, "else", 4) == 0)
            { // 处理 else 语句
                if_condition = !if_condition;
                continue;
            }

            if (strncmp(line, "while", 5) == 0)
            { // 处理 while 循环
                int condition_value;
                sscanf(line, "while %d", &condition_value);
                if (condition_value == 0)
                {
                    // 如果条件为假，跳过整个循环
                    while (fgets(line, MAX_COMMAND_LENGTH, file))
                    {
                        if (strncmp(line, "endwhile", 8) == 0)
                        {
                            break;
                        }
                    }
                }
                continue;
            }

            if (strncmp(line, "endwhile", 8) == 0)
            {                                             // 处理 endwhile
                fseek(file, -strlen(line) - 1, SEEK_CUR); // 回到 while 开始处
                continue;
            }

            if (!if_condition)
            { // 如果条件为假，跳过命令
                continue;
            }

            if (strncmp(line, "jmp", 3) == 0)
            { // 处理无条件跳转指令
                char label_name[MAX_COMMAND_LENGTH];
                sscanf(line, "jmp %s", label_name);

                long label_position = find_label_position(file, labels, label_count, label_name);
                if (label_position == -1)
                {
                    printf("Error: Label '%s' not found\n", label_name);
                    break;
                }

                fseek(file, label_position, SEEK_SET); // 跳转到标签位置
                continue;
            }

            if (strncmp(line, "jmp_if_not_zero", 15) == 0)
            { // 处理条件跳转指令
                char label_name[MAX_COMMAND_LENGTH];
                int address;
                sscanf(line, "jmp_if_not_zero %d %s", &address, label_name);

                int value = memory_use(1, address, 0, memory); // 读取内存地址的值
                if (value != 0)
                { // 如果值不为零，则跳转
                    long label_position = find_label_position(file, labels, label_count, label_name);
                    if (label_position == -1)
                    {
                        printf("Error: Label '%s' not found\n", label_name);
                        break;
                    }

                    fseek(file, label_position, SEEK_SET); // 跳转到标签位置
                }
                continue;
            }

            if (strncmp(line, "exec", 4) == 0)
            { // 处理嵌套宏调用
                char nested_macro_name[MAX_MACRO_NAME_LENGTH];
                sscanf(line, "exec %s", nested_macro_name);
                execute_macro(nested_macro_name, memory, argc, argv); // 递归调用 execute_macro
                continue;
            }

            // 处理普通命令
            char command;
            char first_input_str[MAX_COMMAND_LENGTH], second_input_str[MAX_COMMAND_LENGTH], output_place_str[MAX_COMMAND_LENGTH];
            int output_place;
            sscanf(line, " %c %s %s %s", &command, first_input_str, second_input_str, output_place_str);
            output_place = atoi(output_place_str);
            process_command(command, first_input_str, second_input_str, output_place, memory);
        }
    }
    else
    {
        // 如果没有参数定义，直接执行宏内容
        Label labels[MAX_LABELS];
        int label_count = 0;

        // 第一次扫描：记录所有标签的位置
        char line[MAX_COMMAND_LENGTH];
        long position = ftell(file);
        while (fgets(line, MAX_COMMAND_LENGTH, file))
        {
            if (line[strlen(line) - 1] == '\n')
            {
                line[strlen(line) - 1] = '\0'; // 去掉换行符
            }

            if (strstr(line, ":") != NULL)
            { // 找到标签
                strcpy(labels[label_count].name, line);
                labels[label_count].position = position;
                label_count++;
            }
            position = ftell(file);
        }

        // 第二次扫描：执行命令
        fseek(file, 0, SEEK_SET);
        int if_condition = 1; // 1 表示条件为真，0 表示条件为假
        while (fgets(line, MAX_COMMAND_LENGTH, file))
        {
            if (line[strlen(line) - 1] == '\n')
            {
                line[strlen(line) - 1] = '\0'; // 去掉换行符
            }

            if (strstr(line, ":") != NULL)
            { // 跳过标签行
                continue;
            }

            if (strncmp(line, "if", 2) == 0)
            { // 处理 if 语句
                int condition_value;
                sscanf(line, "if %d", &condition_value);
                if_condition = (condition_value != 0);
                continue;
            }

            if (strncmp(line, "else", 4) == 0)
            { // 处理 else 语句
                if_condition = !if_condition;
                continue;
            }

            if (strncmp(line, "while", 5) == 0)
            { // 处理 while 循环
                int condition_value;
                sscanf(line, "while %d", &condition_value);
                if (condition_value == 0)
                {
                    // 如果条件为假，跳过整个循环
                    while (fgets(line, MAX_COMMAND_LENGTH, file))
                    {
                        if (strncmp(line, "endwhile", 8) == 0)
                        {
                            break;
                        }
                    }
                }
                continue;
            }

            if (strncmp(line, "endwhile", 8) == 0)
            {                                             // 处理 endwhile
                fseek(file, -strlen(line) - 1, SEEK_CUR); // 回到 while 开始处
                continue;
            }

            if (!if_condition)
            { // 如果条件为假，跳过命令
                continue;
            }

            if (strncmp(line, "jmp", 3) == 0)
            { // 处理无条件跳转指令
                char label_name[MAX_COMMAND_LENGTH];
                sscanf(line, "jmp %s", label_name);

                long label_position = find_label_position(file, labels, label_count, label_name);
                if (label_position == -1)
                {
                    printf("Error: Label '%s' not found\n", label_name);
                    break;
                }

                fseek(file, label_position, SEEK_SET); // 跳转到标签位置
                continue;
            }

            if (strncmp(line, "jmp_if_not_zero", 15) == 0)
            { // 处理条件跳转指令
                char label_name[MAX_COMMAND_LENGTH];
                int address;
                sscanf(line, "jmp_if_not_zero %d %s", &address, label_name);

                int value = memory_use(1, address, 0, memory); // 读取内存地址的值
                if (value != 0)
                { // 如果值不为零，则跳转
                    long label_position = find_label_position(file, labels, label_count, label_name);
                    if (label_position == -1)
                    {
                        printf("Error: Label '%s' not found\n", label_name);
                        break;
                    }

                    fseek(file, label_position, SEEK_SET); // 跳转到标签位置
                }
                continue;
            }

            if (strncmp(line, "exec", 4) == 0)
            { // 处理嵌套宏调用
                char nested_macro_name[MAX_MACRO_NAME_LENGTH];
                sscanf(line, "exec %s", nested_macro_name);
                execute_macro(nested_macro_name, memory, argc, argv); // 递归调用 execute_macro
                continue;
            }

            // 处理普通命令
            char command;
            char first_input_str[MAX_COMMAND_LENGTH], second_input_str[MAX_COMMAND_LENGTH], output_place_str[MAX_COMMAND_LENGTH];
            int output_place;
            sscanf(line, " %c %s %s %s", &command, first_input_str, second_input_str, output_place_str);
            output_place = atoi(output_place_str);
            process_command(command, first_input_str, second_input_str, output_place, memory);
        }
    }
    fclose(file);
}
void load_macro(const char *macro_name)
{
    char filename[MAX_MACRO_NAME_LENGTH + 10];
    sprintf(filename, "./%s.txt", macro_name);
    FILE *file = fopen(filename, "r");
    if (file)
    {
        printf("Macro '%s' loaded successfully.\n", macro_name);
        fclose(file);
    }
    else
    {
        printf("Error: Macro '%s' not found\n", macro_name);
    }
}

// 保存文件系统状态到指定文件
void save_filesystem(const char *filename)
{
    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        printf("Error: Failed to save filesystem to '%s'\n", filename);
        return;
    }

    fwrite(&fs, sizeof(FileSystem), 1, file);
    fclose(file);
    printf("Filesystem saved to '%s'\n", filename);
}
// 从硬盘加载文件系统
// 从指定文件加载文件系统状态
void load_filesystem(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        printf("Error: Failed to load filesystem from '%s'\n", filename);
        return;
    }

    fread(&fs, sizeof(FileSystem), 1, file);
    fclose(file);
    printf("Filesystem loaded from '%s'\n", filename);
}
void unload_macro(const char *macro_name)
{
    printf("Macro '%s' unloaded.\n", macro_name);
}
void save_macro_library(const char *library_name)
{
    char filename[MAX_MACRO_NAME_LENGTH + 10];
    sprintf(filename, "./%s.lib", library_name);
    FILE *file = fopen(filename, "w");
    if (file)
    {
        // 将当前所有宏保存到库文件
        for (int i = 0; i < fs.directory_count; i++)
        {
            fprintf(file, "%s\n", fs.directories[i].name);
        }
        fclose(file);
        printf("Macro library '%s' saved successfully.\n", library_name);
    }
    else
    {
        printf("Error: Failed to save macro library\n");
    }
}

void load_macro_library(const char *library_name)
{
    char filename[MAX_MACRO_NAME_LENGTH + 10];
    sprintf(filename, "./%s.lib", library_name);
    FILE *file = fopen(filename, "r");
    if (file)
    {
        char macro_name[MAX_MACRO_NAME_LENGTH];
        while (fgets(macro_name, MAX_MACRO_NAME_LENGTH, file))
        {
            macro_name[strcspn(macro_name, "\n")] = '\0'; // 去掉换行符
            load_macro(macro_name);
        }
        fclose(file);
        printf("Macro library '%s' loaded successfully.\n", library_name);
    }
    else
    {
        printf("Error: Macro library '%s' not found\n", library_name);
    }
}
// 列出所有宏
void list_macros()
{
    printf("Defined macros:\n");
    system("ls ./*.txt");
}

// 删除宏
void delete_macro(char *macro_name)
{
    char filename[MAX_MACRO_NAME_LENGTH + 10];
    sprintf(filename, "./%s.txt", macro_name);

    if (remove(filename) == 0)
    {
        printf("Macro '%s' deleted successfully.\n", macro_name);
    }
    else
    {
        printf("Error: Macro '%s' not found\n", macro_name);
    }
}
// 定义宏 compile_and_run
typedef enum {
    TOKEN_INT,
    TOKEN_IDENT,
    TOKEN_NUMBER,
    TOKEN_PLUS,
    TOKEN_MINUS,
    TOKEN_MUL,
    TOKEN_DIV,
    TOKEN_ASSIGN,
    TOKEN_SEMICOLON,
    TOKEN_LPAREN,
    TOKEN_RPAREN,
    TOKEN_LBRACE,
    TOKEN_RBRACE,
    TOKEN_IF,
    TOKEN_ELSE,
    TOKEN_RETURN,  // 添加这一行
    TOKEN_EOF
} TokenType;

typedef struct
{
    TokenType type;
    char value[MAX_COMMAND_LENGTH];
} Token;

Token tokens[MAX_COMMAND_LENGTH];
int token_count = 0;

void error(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

void lexer(const char *source)
{
    const char *p = source;
    while (*p)
    {
        if (isspace(*p))
        {
            p++;
            continue;
        }

        if (isdigit(*p))
        {
            char num[MAX_COMMAND_LENGTH] = {0};
            int i = 0;
            while (isdigit(*p))
            {
                num[i++] = *p++;
            }
            tokens[token_count].type = TOKEN_NUMBER;
            strcpy(tokens[token_count].value, num);
            token_count++;
            continue;
        }

        if (isalpha(*p))
        {
            char ident[MAX_COMMAND_LENGTH] = {0};
            int i = 0;
            while (isalnum(*p))
            {
                ident[i++] = *p++;
            }
            if (strcmp(ident, "int") == 0)
            {
                tokens[token_count].type = TOKEN_INT;
            }
            else if (strcmp(ident, "if") == 0)
            {
                tokens[token_count].type = TOKEN_IF;
            }
            else if (strcmp(ident, "else") == 0)
            {
                tokens[token_count].type = TOKEN_ELSE;
            }
            else if (strcmp(ident, "return") == 0)
            {
                tokens[token_count].type = TOKEN_RETURN;
            }
            else
            {
                tokens[token_count].type = TOKEN_IDENT;
                strcpy(tokens[token_count].value, ident);
            }
            token_count++;
            continue;
        }

        switch (*p)
        {
        case '+':
            tokens[token_count++].type = TOKEN_PLUS;
            break;
        case '-':
            tokens[token_count++].type = TOKEN_MINUS;
            break;
        case '*':
            tokens[token_count++].type = TOKEN_MUL;
            break;
        case '/':
            tokens[token_count++].type = TOKEN_DIV;
            break;
        case '=':
            tokens[token_count++].type = TOKEN_ASSIGN;
            break;
        case ';':
            tokens[token_count++].type = TOKEN_SEMICOLON;
            break;
        case '(':
            tokens[token_count++].type = TOKEN_LPAREN;
            break;
        case ')':
            tokens[token_count++].type = TOKEN_RPAREN;
            break;
        case '{':
            tokens[token_count++].type = TOKEN_LBRACE;
            break;
        case '}':
            tokens[token_count++].type = TOKEN_RBRACE;
            break;
        default:
            error("Unknown character");
            break;
        }
        p++;
    }
    tokens[token_count].type = TOKEN_EOF;
}


ASTNode *parse_expression();
ASTNode *parse_statement();

ASTNode *parse_primary()
{
    if (tokens[token_count].type == TOKEN_NUMBER)
    {
        ASTNode *node = malloc(sizeof(ASTNode));
        node->type = AST_NUMBER;
        strcpy(node->value, tokens[token_count].value);
        token_count++;
        return node;
    }
    else if (tokens[token_count].type == TOKEN_IDENT)
    {
        ASTNode *node = malloc(sizeof(ASTNode));
        node->type = AST_VARIABLE;
        strcpy(node->value, tokens[token_count].value);
        token_count++;
        return node;
    }
    else if (tokens[token_count].type == TOKEN_LPAREN)
    {
        token_count++;
        ASTNode *node = parse_expression();
        if (tokens[token_count].type != TOKEN_RPAREN)
        {
            printf("Expected ')'\n");
            return NULL;
        }
        token_count++;
        return node;
    }
    return NULL;
}

ASTNode *parse_binary_op()
{
    ASTNode *left = parse_primary();
    while (tokens[token_count].type == TOKEN_PLUS || tokens[token_count].type == TOKEN_MINUS ||
           tokens[token_count].type == TOKEN_MUL || tokens[token_count].type == TOKEN_DIV)
    {
        ASTNode *node = malloc(sizeof(ASTNode));
        node->type = AST_BINARY_OP;
        node->left = left;
        node->right = parse_primary();
        left = node;
    }
    return left;
}

ASTNode *parse_expression()
{
    return parse_binary_op();
}

ASTNode *parse_statement()
{
    if (tokens[token_count].type == TOKEN_INT)
    {
        token_count++;
        if (tokens[token_count].type != TOKEN_IDENT)
        {
            printf("Expected identifier after 'int'\n");
            return NULL;
        }
        ASTNode *node = malloc(sizeof(ASTNode));
        node->type = AST_VARIABLE;
        strcpy(node->value, tokens[token_count].value);
        token_count++;
        if (tokens[token_count].type != TOKEN_SEMICOLON)
        {
            printf("Expected ';' after variable declaration\n");
            return NULL;
        }
        token_count++;
        return node;
    }
    else if (tokens[token_count].type == TOKEN_IDENT)
    {
        ASTNode *node = malloc(sizeof(ASTNode));
        node->type = AST_ASSIGN;
        strcpy(node->value, tokens[token_count].value);
        token_count++;
        if (tokens[token_count].type != TOKEN_ASSIGN)
        {
            printf("Expected '=' after identifier\n");
            return NULL;
        }
        token_count++;
        node->left = parse_expression();
        if (tokens[token_count].type != TOKEN_SEMICOLON)
        {
            printf("Expected ';' after expression\n");
            return NULL;
        }
        token_count++;
        return node;
    }
    else if (tokens[token_count].type == TOKEN_IF)
    {
        ASTNode *node = malloc(sizeof(ASTNode));
        node->type = AST_IF;
        token_count++;
        if (tokens[token_count].type != TOKEN_LPAREN)
        {
            printf("Expected '(' after 'if'\n");
            return NULL;
        }
        token_count++;
        node->left = parse_expression();
        if (tokens[token_count].type != TOKEN_RPAREN)
        {
            printf("Expected ')' after if condition\n");
            return NULL;
        }
        token_count++;
        node->right = parse_statement();
        return node;
    }
    return NULL;
}
void generate_code(ASTNode *node) {
    if (node == NULL)
        return;

    switch (node->type) {
        case AST_VARIABLE:
            printf("Variable: %s\n", node->value);
            break;
        case AST_NUMBER:
            printf("Number: %s\n", node->value);
            break;
        case AST_BINARY_OP:
            generate_code(node->left);
            generate_code(node->right);
            printf("Binary operation\n");
            break;
        case AST_ASSIGN:
            generate_code(node->left);
            printf("Assign to %s\n", node->value);
            break;
        case AST_IF:
            generate_code(node->left);
            printf("If condition\n");
            generate_code(node->right);
            break;
        case AST_FUNCTION:
            printf("Function: %s\n", node->value);
            generate_code(node->body);  // 使用 body 成员
            break;
        case AST_RETURN:
            generate_code(node->left);
            printf("Return\n");
            break;
        case AST_STRUCT:
            printf("Struct: %s\n", node->value);
            generate_code(node->fields);  // 使用 fields 成员
            break;
        case AST_ARRAY:
            printf("Array: %s\n", node->value);
            generate_code(node->elements);  // 使用 elements 成员
            break;
        case AST_POINTER:
            printf("Pointer: %s\n", node->value);
            generate_code(node->pointee);  // 使用 pointee 成员
            break;
        default:
            error("Unknown AST node type");
            break;
    }
}

void generate_debug_info(ASTNode *node) {
    if (node == NULL)
        return;

    switch (node->type) {
        case AST_VARIABLE:
            printf("Debug: Variable %s\n", node->value);
            break;
        case AST_NUMBER:
            printf("Debug: Number %s\n", node->value);
            break;
        case AST_BINARY_OP:
            generate_debug_info(node->left);
            generate_debug_info(node->right);
            printf("Debug: Binary operation\n");
            break;
        case AST_ASSIGN:
            generate_debug_info(node->left);
            printf("Debug: Assign to %s\n", node->value);
            break;
        case AST_IF:
            generate_debug_info(node->left);
            printf("Debug: If condition\n");
            generate_debug_info(node->right);
            break;
        case AST_FUNCTION:
            printf("Debug: Function %s\n", node->value);
            generate_debug_info(node->body);  // 使用 body 成员
            break;
        case AST_RETURN:
            generate_debug_info(node->left);
            printf("Debug: Return\n");
            break;
        case AST_STRUCT:
            printf("Debug: Struct %s\n", node->value);
            generate_debug_info(node->fields);  // 使用 fields 成员
            break;
        case AST_ARRAY:
            printf("Debug: Array %s\n", node->value);
            generate_debug_info(node->elements);  // 使用 elements 成员
            break;
        case AST_POINTER:
            printf("Debug: Pointer %s\n", node->value);
            generate_debug_info(node->pointee);  // 使用 pointee 成员
            break;
        default:
            error("Unknown AST node type");
            break;
    }
}
// 增加对标准库函数的支持
typedef struct
{
    char name[MAX_COMMAND_LENGTH];
    void (*func)(void);
} LibraryFunction;

LibraryFunction library_functions[MAX_MACRO_NAME_LENGTH];
int library_function_count = 0;

// 查找库函数
LibraryFunction *find_library_function(const char *name)
{
    for (int i = 0; i < library_function_count; i++)
    {
        if (strcmp(library_functions[i].name, name) == 0)
        {
            return &library_functions[i];
        }
    }
    return NULL;
}

// 示例库函数
void example_library_function()
{
    printf("Example library function called\n");
}

// 注册库函数
void register_library_function(const char *name, void (*func)(void))
{
    if (library_function_count >= MAX_MACRO_NAME_LENGTH)
    {
        error("Maximum number of library functions reached");
    }

    strcpy(library_functions[library_function_count].name, name);
    library_functions[library_function_count].func = func;
    library_function_count++;
}

// 初始化库函数
void init_library_functions()
{
    register_library_function("example", example_library_function);
}

// 处理库函数调用
void handle_library_function_call(const char *name)
{
    LibraryFunction *func = find_library_function(name);
    if (func == NULL)
    {
        error("Library function not found");
    }

    func->func();
}
void compile_c_code(const char *source)
{
    if (source == NULL)
    {
        printf("Error: No source code provided\n");
        return;
    }

    lexer(source);
    ASTNode *root = parse_statement();
    generate_code(root);
}
// 导入并编译C代码
void import_and_compile(const char *filename)
{
    char *source = read_c_code_from_file(filename);
    if (source == NULL)
    {
        return;
    }

    compile_c_code(source);
    free(source); // 释放内存
}
void compile_and_run()
{
    char source[MAX_COMMAND_LENGTH * 10] = {0};
    printf("Enter your C code (type 'end' on a new line to finish):\n");
    char line[MAX_COMMAND_LENGTH];
    while (1)
    {
        fgets(line, MAX_COMMAND_LENGTH, stdin);
        if (strcmp(line, "end\n") == 0)
        {
            break;
        }
        strcat(source, line);
    }

    compile_c_code(source);
}
// 变量表结构体
typedef struct
{
    char name[MAX_COMMAND_LENGTH];
    int value;
} Variable;

Variable variables[MAX_MACRO_NAME_LENGTH];
int variable_count = 0;

// 查找变量
int find_variable(const char *name)
{
    for (int i = 0; i < variable_count; i++)
    {
        if (strcmp(variables[i].name, name) == 0)
        {
            return variables[i].value;
        }
    }
    return 0; // 默认返回 0
}

// 设置变量
void set_variable(const char *name, int value)
{
    for (int i = 0; i < variable_count; i++)
    {
        if (strcmp(variables[i].name, name) == 0)
        {
            variables[i].value = value;
            return;
        }
    }
    // 如果变量不存在，则新增
    strcpy(variables[variable_count].name, name);
    variables[variable_count].value = value;
    variable_count++;
}
// 从文件中读取C代码
char *read_c_code_from_file(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("Error: Failed to open file '%s'\n", filename);
        return NULL;
    }

    // 获取文件大小
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 分配内存并读取文件内容
    char *source = (char *)malloc(file_size + 1);
    if (source == NULL)
    {
        printf("Error: Failed to allocate memory for file content\n");
        fclose(file);
        return NULL;
    }

    fread(source, 1, file_size, file);
    source[file_size] = '\0'; // 确保字符串以 null 结尾

    fclose(file);
    return source;
}
// 检查挂载点是否存在
int is_mount_point_exist(const char *mount_path)
{
    for (int i = 0; i < fs.mount_point_count; i++)
    {
        if (strcmp(fs.mount_points[i].mount_path, mount_path) == 0)
        {
            return 1; // 挂载点存在
        }
    }
    return 0; // 挂载点不存在
}
// 列出所有挂载点
void list_mount_points()
{
    printf("Current mount points:\n");
    for (int i = 0; i < fs.mount_point_count; i++)
    {
        printf("Mount path: %s, External path: %s\n",
               fs.mount_points[i].mount_path,
               fs.mount_points[i].external_path);
    }
}
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>

// 设置防火墙规则
void set_firewall_rule()
{
    // 这里可以使用 iptables 命令来设置防火墙规则
    system("iptables -A INPUT -p tcp --dport 80 -j ACCEPT");
}

// 配置网络接口
void configure_network_interface(const char *interface_name, const char *ip_address)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    // 设置 IP 地址
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip_address, &addr->sin_addr);

    if (ioctl(fd, SIOCSIFADDR, &ifr) < 0)
    {
        perror("ioctl SIOCSIFADDR failed");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // 启用接口
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
    {
        perror("ioctl SIOCGIFFLAGS failed");
        close(fd);
        exit(EXIT_FAILURE);
    }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
    {
        perror("ioctl SIOCSIFFLAGS failed");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
}
// 创建子进程
pid_t create_child_process()
{
    pid_t pid = fork();
    if (pid < 0)
    {
        perror("fork failed");
        exit(EXIT_FAILURE);
    }
    return pid;
}

// 使用管道进行进程间通信
void process_with_pipe()
{
    int pipefd[2];
    if (pipe(pipefd) == -1)
    {
        perror("pipe failed");
        exit(EXIT_FAILURE);
    }

    pid_t pid = create_child_process();
    if (pid == 0)
    {
        // 子进程
        close(pipefd[1]);              // 关闭写端
        dup2(pipefd[0], STDIN_FILENO); // 将读端重定向到标准输入
        close(pipefd[0]);

        // 执行某个命令，例如 ls
        execlp("ls", "ls", NULL);
        perror("execlp failed");
        exit(EXIT_FAILURE);
    }
    else
    {
        // 父进程
        close(pipefd[0]);               // 关闭读端
        dup2(pipefd[1], STDOUT_FILENO); // 将写端重定向到标准输出
        close(pipefd[1]);

        // 写入数据到管道
        write(STDOUT_FILENO, "Hello from parent\n", 18);
        wait(NULL); // 等待子进程结束
    }
}
// 主函数
int main()
{
    // 检查是否在虚拟机中运行
    //int is_vm = is_running_in_vm();

    // 设置 seccomp 过滤器
    //setup_seccomp(is_vm);

    // 降低权限
    //drop_privileges(is_vm);

    // 配置网络接口
    //configure_network_interface("eth0", "192.168.1.100");

    // 设置防火墙规则
    //set_firewall_rule();

    // 创建子进程并使用管道进行通信
    //process_with_pipe();

    char command[MAX_COMMAND_LENGTH];
    char first_input_str[MAX_COMMAND_LENGTH];
    char second_input_str[MAX_COMMAND_LENGTH];
    char output_place_str[MAX_COMMAND_LENGTH];
    int first_input, second_input, output_place;
    Memory memory = {0};

    // 初始化文件系统
    strcpy(fs.current_directory, "root");
    create_directory("root");
    // 加载文件系统
    load_filesystem("filesystem.dat");

    printf("Welcome to the Computer System Simulator\n");
    printf("Available commands: +, -, *, /, %%, &, |, ^, =, def, exec, list, del\n");
    printf("New commands: m (mkdir), t (touch), c (cd), p (print file), d (delete file), l (list directory)\n");
    printf("Network commands: s (send data to server), g (receive data from server)\n");
    printf("Pointer commands: & (get address), * (dereference), p (pointer add), s (pointer sub)\n");
    printf("Compiler commands: compile_and_run, import_and_compile\n");
    printf("Input format: If the first digit is '0', it is treated as a memory address; otherwise, it is treated as an immediate value.\n");
    printf("Type 'q' to quit.\n");

    while (1)
    {
        printf("Enter command: ");
        scanf("%s", command);

        if (strcmp(command, "q") == 0)
        {
            // 保存文件系统
            save_filesystem("filesystem.dat");
            break;
        }
        else if (strcmp(command, "def") == 0)
        {
            char macro_name[MAX_MACRO_NAME_LENGTH];
            printf("Enter macro name: ");
            scanf("%s", macro_name);
            define_macro(macro_name);
        }
        else if (strcmp(command, "exec") == 0)
        {
            char macro_name[MAX_MACRO_NAME_LENGTH];
            printf("Enter macro name: ");
            scanf("%s", macro_name);

            // 读取参数
            char args[MAX_COMMAND_LENGTH];
            printf("Enter arguments (space separated): ");
            getchar(); // 清除缓冲区
            fgets(args, MAX_COMMAND_LENGTH, stdin);

            // 解析参数
            char *argv[MAX_MACRO_NAME_LENGTH];
            int argc = 0;
            char *token = strtok(args, " \n");
            while (token != NULL)
            {
                argv[argc++] = token;
                token = strtok(NULL, " \n");
            }

            execute_macro(macro_name, &memory, argc, argv);
        }
        else if (strcmp(command, "list") == 0)
        {
            list_macros();
        }
        else if (strcmp(command, "del") == 0)
        {
            char macro_name[MAX_MACRO_NAME_LENGTH];
            printf("Enter macro name: ");
            scanf("%s", macro_name);
            delete_macro(macro_name);
        }
        else if (strcmp(command, "compile_and_run") == 0)
        {
            // 调用 compile_and_run 宏
            compile_and_run();
        }
        else if (strcmp(command, "import_and_compile") == 0)
        {
            char filename[MAX_COMMAND_LENGTH];
            printf("Enter filename: ");
            scanf("%s", filename);
            import_and_compile(filename);
        }
        else if (strcmp(command, "mount") == 0)
        {
            char mount_path[MAX_COMMAND_LENGTH];
            char external_path[MAX_COMMAND_LENGTH];
            printf("Enter mount path: ");
            scanf("%s", mount_path);
            printf("Enter external path: ");
            scanf("%s", external_path);
            mount_external(mount_path, external_path);
        }
        else if (strcmp(command, "unmount") == 0)
        {
            char mount_path[MAX_COMMAND_LENGTH];
            printf("Enter mount path: ");
            scanf("%s", mount_path);
            unmount_external(mount_path);
        }
        else if (strcmp(command, "list_mounts") == 0)
        {
            list_mount_points();
        }
        else
        {
            // 修改 main 函数中的参数传递
            printf("Enter first input: ");
            scanf("%s", first_input_str);
            printf("Enter second input: ");
            scanf("%s", second_input_str);
            printf("Enter output address: ");
            scanf("%s", output_place_str);
            output_place = atoi(output_place_str);
            process_command(command[0], first_input_str, second_input_str, output_place, &memory);
        }
    }

    printf("Exiting simulator. Goodbye!\n");
    return 0;
}
