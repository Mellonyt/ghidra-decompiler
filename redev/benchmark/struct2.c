#include <stdio.h>

struct simple_st{
    int m;
    int n;
};

int sum_up(struct simple_st *s, struct simple_st *t) {
    return (s->m * t->m) - (s->n * t->n);
}

int main(int argc, char* argv[])
{
    struct simple_st s = {10, 20};
    struct simple_st t = {20, 10};
    int sum;

    sum = sum_up(&s, &t);

    return 0;
}
