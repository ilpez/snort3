void kernel ac_gpu(__global int *stateArray, __global uchar *xlatcase,
                   __global const uchar *TxBuf, __global int *nBuf,
                   __global int *result) {

  int globalId = get_global_id(0);

  int n = nBuf[globalId];
  uchar *Tx = &(TxBuf[globalId * n]);

  int state = 0;
  int nfound = 0;
  int sindex;

  for (int i = 0; i < n; i++) {
    sindex = xlatcase[Tx[i]];
    if (stateArray[state * 258 + 1] == 1) {
      // for (mlist = MatchList[state]; mlist; mlist = (*mlist).next) {
      //   // mlist = MatchList[state];
      //   if ((*mlist).nocase ||
      //       (memcmp((*mlist).casepatrn, T - (*mlist).n, (*mlist).n) == 0)) {
      //     nfound++;
      //   }
      // }
      nfound++;
      result[globalId * n + i] = state;
    }
    state = stateArray[state * 258 + 2u + sindex];
  }
  // result[0] = 1;
}