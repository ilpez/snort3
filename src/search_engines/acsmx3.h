#ifndef ACSMX3_H
#define ACSMX3_H

#include <cstdint>
#include "search_common.h"

#define CL_HPP_TARGET_OPENCL_VERSION 200
#include "CL/cl2.hpp"

namespace snort
{
    struct SnortConfig;
}

typedef unsigned int acstate_t;
#define ACSM_FAIL_STATE3 0xffffffff

struct ACSM_PATTERN3
{
    ACSM_PATTERN3 *next;
    uint8_t *patrn;
    uint8_t *casepatrn;

    void *udata;
    void *rule_option_tree;
    void *neg_list;

    int n;
    int nocase;
    int negative;
};

struct trans_node_t
{
    acstate_t key;
    acstate_t next_state;
    trans_node_t *next;
};

struct ACSM_STRUCT3
{
    ACSM_PATTERN3 *acsmPatterns;
    acstate_t *acsmFailState;
    ACSM_PATTERN3 **acsmMatchList;

    trans_node_t **acsmTransTable;
    acstate_t **acsmNextState;
    const MpseAgent *agent;

    int acsmMaxStates;
    int acsmNumStates;

    int acsmNumTrans;
    int acsmAlphabetSize;
    int numPatterns;

    int sizeofstate;
    int compress_states;
};
/*
    Function Prototypes
*/

void acsmx3_init_xlatcase();

ACSM_STRUCT3 *acsmNew3(const MpseAgent *);

int acsmAddPattern3(
    ACSM_STRUCT3 *p, const uint8_t *pat, unsigned n,
    bool nocase, bool negative, void *id);

int acsmCompile3(snort::SnortConfig *, ACSM_STRUCT3 *);

int acsm_search_dfa_gpu(
    ACSM_STRUCT3 *, const uint8_t *Tx, int n, MpseMatch,
    void *context, int *current_state);

void acsmFree3(ACSM_STRUCT3 *);
int acsmPatternCount3(ACSM_STRUCT3 *);
void acsmCompressStates(ACSM_STRUCT3 *, int);

void acsmPrintInfo3(ACSM_STRUCT3 *p);

int acsmPrintDetailInfo3(ACSM_STRUCT3 *);
int acsmPrintSummaryInfo3();
void acsm3_init_summary();

#endif