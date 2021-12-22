void kernel ac_gpu(__global int *stateArray, __global uchar *xlatcase,
                   __global uchar *Tx, __global int *n, __global int *result) {

  // uint i = get_global_id(0);
  // int window = ((*n) / 768);
  // int startPosition = i * window;
  // int limit = startPosition + window + 9;
  uchar *T;
  uchar *Tend;

  T = Tx;
  Tend = Tx + (int)&n;
  int state = 0;
  int nfound = 0;
  int index;
  int sindex;

  for (; T < Tend; T++) {
    // for (int j = startPosition; j < limit && j < *n; j++) {
    sindex = xlatcase[T[0]];
    if (stateArray[(state * 258) + 1] == 1) {
      index = T - Tx;
      nfound++;
      result[index] = state;
    }
    state = stateArray[(state * 258) + 2u + sindex];
  }
  result[0] = nfound;
}