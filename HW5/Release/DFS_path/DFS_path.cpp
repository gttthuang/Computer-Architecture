#include <iostream>
#include <vector>

using namespace std;

// Reference:https://www.geeksforgeeks.org/problems/root-to-leaf-paths/1?page=1&category=Recursion&sortBy=submissions
//===============testcase1=======================
int input[] = {1, 2, 3, 4, 5};
int size = 5;
// output:
//  1 2 4
//  1 2 5
//  1 3
//================================================

//===============testcase2=======================
// int input[] = {1, 3, 5, 10, 40, 60, 70};
// int size = 7;
// output:
//  1 3 10
//  1 3 40
//  1 5 60
//  1 5 70
//================================================

void dfs(int n, vector<int> &vc)
{
    if (n >= size)
        return;
    vc.push_back(input[n]);
    if (n * 2 + 1 >= size && n * 2 + 2 >= size)
    {
        for (auto x : vc)
            cout << x << " ";
        cout << endl;
        vc.pop_back();
        return;
    }
    dfs(n * 2 + 1, vc);
    dfs(n * 2 + 2, vc);
    vc.pop_back();
}

int main(void)
{
    vector<int> vc;
    dfs(0, vc);
    return 0;
}
