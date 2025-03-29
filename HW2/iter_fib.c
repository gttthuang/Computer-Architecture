#include <stdio.h>
int iter_fibonacci(int num){
    int fib1, fib2, fib;
    fib1 = fib2 = 1;

    if(num == 1 || num ==2){return fib1;}
    for(int i=2; i<num; i++){
        fib = fib1 + fib2;
        fib2 = fib1;
        fib1 = fib;
    }
    return fib;
}

int main(){
    int fib = iter_fibonacci(7);
    printf("%d", fib);
    return 0;
}