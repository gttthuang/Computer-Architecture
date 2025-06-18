.data

# ==========testcase1===========
input:  .word 1, 3, 5, 10, 40, 60, 70  
size:   .word 7
# output: 
#  1 3 10
#  1 3 40
#  1 5 60
#  1 5 70
# ==============================

# ==========testcase2===========
#input:  .word 1, 2, 3, 4, 5                   
#size:   .word 5 
# output:
#  1 2 4
#  1 2 5
#  1 3
# ============================== 
newline: .asciz "\n"               

.text
.globl main


# Start your coding below, don't change anything upper except testing different testcase
main:


