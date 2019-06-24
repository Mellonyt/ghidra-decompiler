#include <stdio.h>

struct simple_st{
    int m;
    int n;
};

int sum_up(struct simple_st *s) {
    return s->m + s->n;
}

int main(int argc, char* argv[])
{
    struct simple_st s = {10, 20};
    int sum;

    sum = sum_up(&s);

    return 0;
}
