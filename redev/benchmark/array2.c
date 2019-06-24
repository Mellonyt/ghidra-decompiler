int loop1() {
    int arr[20];
    int i;

    for (i = 0; i < 20; i++) {
        arr[i] = i;
    }
    return 0;
}

void loop2(int *arr, int len) {
    int i;

    for (i = 0; i < len; i++) {
        arr[i] = i;
    }
}

int main (int argc, char *argv[])
{
    loop1();

    int arr[20];
    loop2(arr, 20);

    return 0;

}
