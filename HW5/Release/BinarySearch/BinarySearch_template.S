.data
.align 4


# ================testcase1===================
A: .word 2, 3, 4, 10, 40, 45, 50, 60, 70, 80, 90, 90, 98, 111, 112, 113, 114
Q: .word 45
low: .word 0
high: .word 16
strNoFoundOutput: .string "Element is not present in array"
strFoundOutput: .string "Element is present at index "
# output: Element is present at index 5
# ============================================

# ================testcase2===================
# A: .word 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40
# Q: .word 29
# low: .word 0
# high: .word 39
# strNoFoundOutput: .string "Element is not present in array"
# strFoundOutput: .string "Element is present at index "
# output: Element is not present in array
# ============================================

.text
.global _start


# Start your coding below, don't change anything upper except testing different testcase
_start:

