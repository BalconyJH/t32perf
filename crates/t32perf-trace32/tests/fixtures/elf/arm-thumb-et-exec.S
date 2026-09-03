.syntax unified
.cpu cortex-m0plus
.thumb

.section .text._start,"ax",%progbits
.global _start
.type _start,%function
.thumb_func
_start:
    b first
.size _start, .-_start

.section .text.first,"ax",%progbits
.global first
.global first_alias
.type first,%function
.type first_alias,%function
.thumb_func
first:
first_alias:
    nop
    bx lr
.size first, .-first
.size first_alias, .-first_alias

.section .text.second,"ax",%progbits
.global second
.type second,%function
.thumb_func
second:
    nop
    nop
    bx lr
.size second, .-second
