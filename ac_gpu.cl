void kernel ac_gpu(__global int *stateArray, __global uchar *xlatcase,
                   __global uchar *Tx, __global int *n, __global int *result) {

  int state = 0;
  int nfound = 0;
  int sindex;

  for (int i = 0; i < *n; i++) {
    sindex = xlatcase[Tx[i]];
    if (stateArray[(state * 258) + 1] == 1) {
      nfound++;
      result[i] = state;
    }
    state = stateArray[(state * 258) + 2u + sindex];
  }
  result[0] = nfound;
}