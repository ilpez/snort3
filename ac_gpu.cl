// typedef unsigned int acstate_t;

void kernel ac_gpu(__global int *stateArray, __global uchar *xlatcase,
                   __global uchar *Tx, __global int *n, __global int *result) {

  // uint i = get_global_id(0);

  // int window = ((*n) / 384);
  // int startPosition = i * window;
  // int limit = startPosition + window + 9;
  // result[i] = 0;
  int state = 0;
  int nfound = 0;
  int sindex;

  for (int j = 0; j < *n; j++) {
    sindex = xlatcase[Tx[j]];
    if (stateArray[(state * 258) + 1] == 1) {
      nfound++;
      result[state] = 1;
    }
    state = stateArray[(state * 258) + 2u + sindex];
  }
  result[0] = nfound;
}