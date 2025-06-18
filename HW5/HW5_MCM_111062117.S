.data
.align 4

# ==========testcase1===========
arr: .word 1, 2, 3, 4, 5, 6, 7, 8
length: .word 8
strOutput: .string "The minimum number of multiplications: "
# output: The minimum number of multiplications: 166
# ==============================

# ==========testcase2===========
# arr: .word 5, 6, 3, 4, 1, 2, 9, 10, 7, 8, 5, 6
# length: .word 12
# strOutput: .string "The minimum number of multiplications: "
# output: The minimum number of multiplications: 394
# ==============================

.text
.global _start

# Start your coding below, don't change anything upper except testing different testcase
_start:
    li a0, 0
    lw a1, length
    addi a1, a1, -1  # a1 = j = length - 1

    # call function MCM
    jal MCM

    # print result
    # Save the result from MCM
    mv t0, a0
    
    # Print the string
    la a0, strOutput
    li a7, 4
    ecall
    
    # Print the result integer
    mv a0, t0
    li a7, 1
    ecall
    
    j END

MCM:
    addi sp, sp, -80
    sd ra, 0(sp)  # Save return address
    sd s0, 8(sp)  # Save s0-s8
    sd s1, 16(sp)
    sd s2, 24(sp)
    sd s3, 32(sp)
    sd s4, 40(sp)
    sd s5, 48(sp)
    sd s6, 56(sp)
    sd s7, 64(sp)
    sd s8, 72(sp)

    mv s0, a0  # s0 = i
    mv s1, a1  # s1 = j
    addi s2, s0, 1  # s2 = k = i + 1
    li s3, 0  # s3 = res = 0

    bge s2, s1, RETURN
    li s3, 2047  # res = 2047 (max value)
    
LOOP_K:
    bge s2, s1, END_LOOP
    # recursive call MCM(i, k)
    mv a0, s0
    mv a1, s2
    jal MCM
    
    mv s4, a0  # s4 = MCM(i, k)

    # recursive call MCM(k, j)
    mv a0, s2
    mv a1, s1
    jal MCM
    
    add s4, s4, a0  # s4 = MCM(i, k) + MCM(k, j)
    
    # Calculate arr[i], arr[k], arr[j]
    slli t0, s0, 2
    la t1, arr
    add t0, t1, t0
    lw s5, 0(t0)  # s5 = arr[i]
    
    slli t0, s2, 2
    add t0, t1, t0
    lw s6, 0(t0)  # s6 = arr[k]
    
    slli t0, s1, 2
    add t0, t1, t0
    lw s7, 0(t0)  # s7 = arr[j]

    mul s8, s5, s6
    mul s8, s8, s7
    add s4, s4, s8  # s4 += arr[i] * arr[k] * arr[j]

    bge s4, s3, SKIP_UPDATE
    mv s3, s4
SKIP_UPDATE:
    addi s2, s2, 1  # k++
    j LOOP_K

END_LOOP:
    nop

RETURN:
    mv a0, s3
    ld ra, 0(sp)
    ld s0, 8(sp)
    ld s1, 16(sp)
    ld s2, 24(sp)
    ld s3, 32(sp)
    ld s4, 40(sp)
    ld s5, 48(sp)
    ld s6, 56(sp)
    ld s7, 64(sp)
    ld s8, 72(sp)
    addi sp, sp, 80
    jr ra

END:
    nop