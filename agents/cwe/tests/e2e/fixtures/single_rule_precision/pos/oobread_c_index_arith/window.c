/* C does not check an index: arr[i + offset] past the end reads whatever is there. */
int window_sum(const int *arr, int i, int offset) {
    /* EXPECT-NEXT: finding */
    int v = arr[i + offset];
    return v;
}
