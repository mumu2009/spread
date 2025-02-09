ENTRY(_start)

MEMORY
{
    RAM : ORIGIN = 0x40000000, LENGTH = 64M
}

SECTIONS
{
    . = ORIGIN(RAM);
    .text :
    {
        *(.text)
    }
    .rodata :
    {
        *(.rodata)
    }
    .data :
    {
        *(.data)
    }
    .bss :
    {
        *(.bss)
    }
}