void kernel ac_gpu(__global const int *stateArray,
                   __global const int *matchArray,
                   __global const uchar *xlatcase, __global const uchar *TxBuf,
                   __global const int *nBuf, __global int *result) {

  unsigned int globalId = get_global_id(0);
  int kernelSize = get_global_size(0);
  int partitionSize = *nBuf / kernelSize;
  int start = globalId * partitionSize;
  int stop = start + partitionSize + 9;

  int state = 0;
  int nfound = 0;
  int sindex;

  for (int i = start; i < *nBuf && i < stop; i++) {
    sindex = xlatcase[TxBuf[i]];
    if (stateArray[state * 258 + 1] == 1) {
      if (i >= matchArray[state] &&
          (i - matchArray[state]) <= (start + partitionSize)) {
        nfound += 1;
      }
    }
    state = stateArray[state * 258 + 2u + sindex];
  }
  result[globalId] = nfound;
}