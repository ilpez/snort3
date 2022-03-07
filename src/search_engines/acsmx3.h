#ifndef ACSMX3_H
#define ACSMX3_H

#include <cstdint>
#include "search_common.h"
#include "main.h"

#define CL_HPP_TARGET_OPENCL_VERSION 200
#define CL_HPP_ENABLE_EXCEPTIONS
#include "CL/cl2.hpp"
#include <vector>
#include <fstream>
#include <iostream>

namespace snort
{
    struct SnortConfig;
}

typedef unsigned int acstate_t;
#define ACSM_FAIL_STATE3 0xffffffff

#define KERNEL_SIZE 3072

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

    cl_int err;

    // OpenCL Device Constructor
    cl::Platform platform;
    cl::Device device;

    // OpenCL Kernel Constructor
    cl::Context context;
    cl::Program::Sources source;
    cl::Program program;

    // OpenCL Kernel Execution
    cl::Kernel kernel;
    cl::CommandQueue queue;
    cl::Event search_event;

    // OpenCL Shared Data Structure
    int buffer_size;
    uint8_t *tx_map_ptr;
    int packet_length_buffer;
    int *stateArray;
    int *matchArray;
    int *resultArray;

    // OpenCL Input Buffer
    cl::Buffer cl_stateTable; // int
    cl::Buffer cl_matchTable;
    cl::Buffer cl_xlatcase;   // uint8_t x 256
    cl::Buffer cl_Tx;         // uint8_t
    // cl::Buffer cl_n;          // int

    // OpenCL Output Buffer
    cl::Buffer cl_result;
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

// void gpu_search(ACSM_STRUCT3 *);
void acsmFree3(ACSM_STRUCT3 *);
int acsmPatternCount3(ACSM_STRUCT3 *);
void acsmCompressStates(ACSM_STRUCT3 *, int);

void acsmPrintInfo3(ACSM_STRUCT3 *p);

int acsmPrintDetailInfo3(ACSM_STRUCT3 *);
int acsmPrintSummaryInfo3();
void acsm3_init_summary();

#endif
