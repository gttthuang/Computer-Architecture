// C++ code to implement the matrix chain multiplication using recursion
#include <iostream>
using namespace std;

// ==============testcase1==============
// int arr[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
// int length = 8;
// output: 166
// =====================================

// ==============testcase2==============
int arr[] = { 5, 6, 3, 4, 1, 2, 9, 10, 7, 8, 5, 6 };
int length = 12;
// output: 394
// =====================================


// Matrix Ai has dimension arr[i-1] x arr[i]
int matrixMultiplication(int i, int j) {

    int k = i + 1;
    int res = 0;
    int curr = 0;

    // If length of chain is more than 2
    if (k < j) {

        // The maximum value could be store in the register is 2047
        res = 2047;

        // If there is only one matrix
        // Place the first bracket at different
        // positions or k and for every placed
        // first bracket, recursively compute
        // minimum cost for remaining brackets
        // (or subproblems)
        for (k; k < j; k++) {
            curr = matrixMultiplication(i, k) + matrixMultiplication(k, j) + arr[i] * arr[k] * arr[j];
            res = min(curr, res);
        }

    }

    // Return minimum count
    return res;
}

// Return the small one
int min(int curr, int res) {
    if (res < curr)
        return res;
    else
        return curr;
}

int main() {
    int minNumber = matrixMultiplication(0, length - 1);
    cout << "The minimum number of multiplications: " << minNumber << endl;
    return 0;
}