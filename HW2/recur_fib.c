#include <stdio.h>

int recur_fibonacci(int num){
    int fib1, fib2, fib;
    fib1 = fib2 = 1;
    if(num == 1 || num ==2){return fib1;}

    fib = recur_fibonacci(num - 1) + recur_fibonacci(num - 2);
    return fib;
}

int main(){
    int fib = recur_fibonacci(7);
    printf("%d", fib);
    return 0;
}