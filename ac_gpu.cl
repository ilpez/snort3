void kernel ac_gpu(__global const int *stateArray,
                   __global const uchar *xlatcase, __global const uchar *TxBuf,
                   __global const int *nBuf, __global int *result) {

  // int size_per_workgroup = *nBuf / 384;
  // int start = size_per_workgroup * get_global_id(0);
  // int stop = start + size_per_workgroup;
  unsigned int globalId = get_global_id(0);
  int n = nBuf[globalId];
  uchar *Tx = &(TxBuf[globalId * n]);

  int state = 0;
  int nfound = 0;
  int sindex;

  for (int i = 0; i < n; i++) {
    sindex = xlatcase[TxBuf[i]];
    if (stateArray[state * 258 + 1] == 1) {
      nfound++;
      // barrier(CLK_GLOBAL_MEM_FENCE);
    }
    state = stateArray[state * 258 + 2u + sindex];
  }
  result[globalId] = nfound;
  // barrier(CLK_GLOBAL_MEM_FENCE);
}