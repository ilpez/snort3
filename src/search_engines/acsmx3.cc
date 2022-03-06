#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "acsmx3.h"

#include <cassert>
#include <list>

#include "log/messages.h"
#include "utils/stats.h"
#include "utils/util.h"

using namespace snort;

#define printf LogMessage

static int acsm3_total_memory = 0;
static int acsm3_pattern_memory = 0;
static int acsm3_matchlist_memory = 0;
static int acsm3_transtable_memory = 0;
static int acsm3_dfa_memory = 0;
static int acsm3_dfa1_memory = 0;
static int acsm3_dfa2_memory = 0;
static int acsm3_dfa4_memory = 0;
static int acsm3_failstate_memory = 0;

struct acsm_summary_t
{
    unsigned num_states;
    unsigned num_transitions;
    unsigned num_instances;
    unsigned num_patterns;
    unsigned num_characters;
    unsigned num_match_states;
    unsigned num_1byte_instances;
    unsigned num_2byte_instances;
    unsigned num_4byte_instances;
    ACSM_STRUCT3 acsm;
};

static acsm_summary_t summary;

void acsm3_init_summary()
{
    summary.num_states = 0;
    summary.num_transitions = 0;
    summary.num_instances = 0;
    summary.num_patterns = 0;
    summary.num_characters = 0;
    summary.num_match_states = 0;
    summary.num_1byte_instances = 0;
    summary.num_2byte_instances = 0;
    summary.num_4byte_instances = 0;
    memset(&summary.acsm, 0, sizeof(ACSM_STRUCT3));
    acsm3_total_memory = 0;
    acsm3_pattern_memory = 0;
    acsm3_matchlist_memory = 0;
    acsm3_transtable_memory = 0;
    acsm3_dfa_memory = 0;
    acsm3_failstate_memory = 0;
}

static uint8_t xlatcase[256];

void acsmx3_init_xlatcase()
{
    int i;
    for (i = 0; i < 256; i++)
    {
        xlatcase[i] = (uint8_t)toupper(i);
    }
}

static inline void ConvertCaseEx(uint8_t *d, const uint8_t *s, int m)
{
    int i;
    for (i = 0; i < m; i++)
    {
        d[i] = xlatcase[s[i]];
    }
}

enum Acsm3MemoryTpe
{
    ACSM3_MEMORY_TYPE__NONE = 0,
    ACSM3_MEMORY_TYPE__PATTERN,
    ACSM3_MEMORY_TYPE__MATCHLIST,
    ACSM3_MEMORY_TYPE__TRANSTABLE,
    ACSM3_MEMORY_TYPE__FAILSTATE
};

static void *AC_MALLOC(int n, Acsm3MemoryTpe type)
{
    void *p = snort_calloc(n);

    switch (type)
    {
    case ACSM3_MEMORY_TYPE__PATTERN:
        acsm3_pattern_memory += n;
        break;
    case ACSM3_MEMORY_TYPE__MATCHLIST:
        acsm3_matchlist_memory += n;
        break;
    case ACSM3_MEMORY_TYPE__TRANSTABLE:
        acsm3_transtable_memory += n;
        break;
    case ACSM3_MEMORY_TYPE__FAILSTATE:
        acsm3_failstate_memory += n;
        break;
    case ACSM3_MEMORY_TYPE__NONE:
        break;
    default:
        assert(false);
    }

    acsm3_total_memory += n;

    return p;
}

static void *AC_MALLOC_DFA(int n, int sizeofstate)
{
    void *p = snort_calloc(n);

    switch (sizeofstate)
    {
    case 1:
        acsm3_dfa1_memory += n;
        break;
    case 2:
        acsm3_dfa2_memory += n;
        break;
    case 4:
    default:
        acsm3_dfa4_memory += n;
        break;
    }

    acsm3_dfa_memory += n;
    acsm3_total_memory += n;

    return p;
}

static void AC_FREE(void *p, int n, Acsm3MemoryTpe type)
{
    if (p != nullptr)
    {
        switch (type)
        {
        case ACSM3_MEMORY_TYPE__PATTERN:
            acsm3_pattern_memory -= n;
            break;
        case ACSM3_MEMORY_TYPE__MATCHLIST:
            acsm3_matchlist_memory -= n;
            break;
        case ACSM3_MEMORY_TYPE__TRANSTABLE:
            acsm3_transtable_memory -= n;
            break;
        case ACSM3_MEMORY_TYPE__FAILSTATE:
            acsm3_failstate_memory -= n;
            break;
        case ACSM3_MEMORY_TYPE__NONE:
        default:
            break;
        }
        acsm3_total_memory -= n;
        snort_free(p);
    }
}

static void AC_FREE_DFA(void *p, int n, int sizeofstate)
{
    if (p != nullptr)
    {
        switch (sizeofstate)
        {
        case 1:
            acsm3_dfa1_memory -= n;
            break;
        case 2:
            acsm3_dfa2_memory -= n;
            break;
        case 4:
        default:
            acsm3_dfa4_memory -= n;
            break;
        }

        acsm3_dfa_memory -= n;
        acsm3_total_memory -= n;
        snort_free(p);
    }
}

static int List_GetNextStateOpt(
    ACSM_STRUCT3 *acsm, trans_node_t **acsmTransTableOpt,
    int state, int input)
{
    int index = state * acsm->acsmAlphabetSize + input;
    trans_node_t *t = acsmTransTableOpt[index];

    if (t)
        return t->next_state;
    if (state == 0)
        return 0;

    return ACSM_FAIL_STATE3;
}

static int List_GetNextState(
    ACSM_STRUCT3 *acsm, int state, int input)
{
    trans_node_t *t = acsm->acsmTransTable[state];

    while (t)
    {
        if (t->key == (acstate_t)input)
        {
            return t->next_state;
        }
        t = t->next;
    }

    if (state == 0)
        return 0;

    return ACSM_FAIL_STATE3;
}

static int List_GetNextState2(
    ACSM_STRUCT3 *acsm, int state, int input)
{
    trans_node_t *t = acsm->acsmTransTable[state];

    while (t)
    {
        if (t->key == (acstate_t)input)
        {
            return t->next_state;
        }
        t = t->next;
    }

    return 0;
}

static int List_PutNextStateOpt(
    ACSM_STRUCT3 *acsm, trans_node_t **acsmTransTableOpt,
    int state, int input, int next_state)
{
    int index = state * acsm->acsmAlphabetSize + input;
    trans_node_t *t = acsmTransTableOpt[index];
    if (t)
    {
        t->next_state = next_state;
        return 0;
    }

    trans_node_t *tnew = (trans_node_t *)AC_MALLOC(sizeof(trans_node_t), ACSM3_MEMORY_TYPE__TRANSTABLE);

    if (!tnew)
        return -1;

    tnew->key = input;
    tnew->next_state = next_state;
    tnew->next = acsm->acsmTransTable[state];
    acsm->acsmTransTable[state] = tnew;
    acsm->acsmNumTrans++;

    acsmTransTableOpt[index] = tnew;

    return 0;
}

static int List_PutNextState(
    ACSM_STRUCT3 *acsm, int state, int input, int next_state)
{
    trans_node_t *p;
    trans_node_t *tnew;

    p = acsm->acsmTransTable[state];
    while (p)
    {
        if (p->key == (acstate_t)input)
        {
            p->next_state = next_state;
            return 0;
        }
        p = p->next;
    }

    tnew = (trans_node_t *)AC_MALLOC(sizeof(trans_node_t), ACSM3_MEMORY_TYPE__TRANSTABLE);

    if (!tnew)
        return -1;

    tnew->key = input;
    tnew->next_state = next_state;
    tnew->next = acsm->acsmTransTable[state];
    acsm->acsmTransTable[state] = tnew;
    acsm->acsmNumTrans++;

    return 0;
}

static int List_FreeTransTable(ACSM_STRUCT3 *acsm)
{
    int i;
    trans_node_t *t, *p;
    if (acsm->acsmTransTable == nullptr)
        return 0;

    for (i = 0; i < acsm->acsmMaxStates; i++)
    {
        t = acsm->acsmTransTable[i];

        while (t != nullptr)
        {
            p = t->next;
            AC_FREE(t, sizeof(trans_node_t), ACSM3_MEMORY_TYPE__TRANSTABLE);
            t = p;
        }
    }

    AC_FREE(acsm->acsmTransTable, sizeof(void *) * acsm->acsmMaxStates, ACSM3_MEMORY_TYPE__TRANSTABLE);

    acsm->acsmTransTable = nullptr;

    return 0;
}

static inline int List_ConvToFull(
    ACSM_STRUCT3 *acsm, acstate_t state, acstate_t *full)
{
    int tcnt = 0;
    trans_node_t *t = acsm->acsmTransTable[state];

    if (t == nullptr)
        return 0;

    while (t != nullptr)
    {
        full[t->key] = t->next_state;
        tcnt++;
        t = t->next;
    }

    return tcnt;
}

static ACSM_PATTERN3 *CopyMatchListEntry(ACSM_PATTERN3 *px)
{
    ACSM_PATTERN3 *p;

    p = (ACSM_PATTERN3 *)AC_MALLOC(sizeof(ACSM_PATTERN3), ACSM3_MEMORY_TYPE__MATCHLIST);

    memcpy(p, px, sizeof(ACSM_PATTERN3));

    return p;
}

static void AddMatchListEntry(
    ACSM_STRUCT3 *acsm, int state, ACSM_PATTERN3 *px)
{
    ACSM_PATTERN3 *p;
    p = (ACSM_PATTERN3 *)AC_MALLOC(sizeof(ACSM_PATTERN3), ACSM3_MEMORY_TYPE__MATCHLIST);

    memcpy(p, px, sizeof(ACSM_PATTERN3));
    p->next = acsm->acsmMatchList[state];

    acsm->acsmMatchList[state] = p;

    acsm->matchArray[state] = p->n;
}

static void AddPatternStates(ACSM_STRUCT3 *acsm, ACSM_PATTERN3 *p)
{
    int state = 0;
    int n = p->n;
    uint8_t *pattern = p->patrn;

    for (; n > 0; pattern++, n--)
    {
        int next = List_GetNextState(acsm, state, *pattern);

        if ((acstate_t)next == ACSM_FAIL_STATE3 || next == 0)
            break;

        state = next;
    }

    for (; n > 0; pattern++, n--)
    {
        acsm->acsmNumStates++;
        List_PutNextState(acsm, state, *pattern, acsm->acsmNumStates);
        state = acsm->acsmNumStates;
    }

    AddMatchListEntry(acsm, state, p);
}

static void Build_NFA(ACSM_STRUCT3 *acsm)
{
    acstate_t *FailState = acsm->acsmFailState;
    ACSM_PATTERN3 **MatchList = acsm->acsmMatchList;
    ACSM_PATTERN3 *mlist, *px;

    std::list<int> queue;

    bool *queue_array = (bool *)snort_calloc(acsm->acsmNumStates, sizeof(bool));

    for (int i = 0; i < acsm->acsmAlphabetSize; i++)
    {
        int s = List_GetNextState2(acsm, 0, i);
        if (s)
        {
            if (!queue_array[s])
            {
                queue.emplace_back(s);
                queue_array[s] = true;
            }
            FailState[s] = 0;
        }
    }

    for (auto r : queue)
    {
        queue_array[r] = false;

        for (int i = 0; i < acsm->acsmAlphabetSize; i++)
        {
            int s = List_GetNextState(acsm, r, i);

            if ((acstate_t)s != ACSM_FAIL_STATE3)
            {
                if (!queue_array[s])
                {
                    queue.emplace_back(s);
                    queue_array[s] = true;
                }

                int fs = FailState[r];
                int next;

                while ((acstate_t)(next = List_GetNextState(acsm, fs, i)) == ACSM_FAIL_STATE3)
                {
                    fs = FailState[fs];
                }

                FailState[s] = next;

                for (mlist = MatchList[next]; mlist; mlist = mlist->next)
                {
                    px = CopyMatchListEntry(mlist);

                    px->next = MatchList[s];
                    MatchList[s] = px;
                }
            }
        }
    }

    snort_free(queue_array);
}

static void Convert_NFA_To_DFA(ACSM_STRUCT3 *acsm)
{
    int cFailState;
    acstate_t *FailState = acsm->acsmFailState;

    std::list<int> queue;
    bool *(queue_array) = (bool *)snort_calloc(acsm->acsmNumStates, sizeof(bool));
    trans_node_t **acsmTransTableOpt = (trans_node_t **)
        snort_calloc(acsm->acsmAlphabetSize * acsm->acsmNumStates, sizeof(trans_node_t *));

    for (int i = 0; i < acsm->acsmNumStates; i++)
    {
        trans_node_t *t = acsm->acsmTransTable[i];
        while (t)
        {
            int index = i * acsm->acsmAlphabetSize + t->key;
            acsmTransTableOpt[index] = t;
            t = t->next;
        }
    }

    for (int i = 0; i < acsm->acsmAlphabetSize; i++)
    {
        if (int s = List_GetNextStateOpt(acsm, acsmTransTableOpt, 0, i))
        {
            if (!queue_array[s])
            {
                queue.emplace_back(s);
                queue_array[s] = true;
            }
        }
    }

    for (auto r : queue)
    {
        queue_array[r] = false;

        for (int i = 0; i < acsm->acsmAlphabetSize; i++)
        {
            int s = List_GetNextStateOpt(acsm, acsmTransTableOpt, r, i);

            if ((acstate_t)s != ACSM_FAIL_STATE3 && s != 0)
            {
                if (!queue_array[s])
                {
                    queue.emplace_back(s);
                    queue_array[s] = true;
                }
            }
            else
            {
                cFailState = List_GetNextStateOpt(acsm, acsmTransTableOpt, FailState[r], i);

                if ((acstate_t)cFailState != ACSM_FAIL_STATE3 && cFailState != 0)
                {
                    List_PutNextStateOpt(acsm, acsmTransTableOpt, r, i, cFailState);
                }
            }
        }
    }

    snort_free(queue_array);
    snort_free(acsmTransTableOpt);
}

static int Conv_List_To_Full(ACSM_STRUCT3 *acsm)
{
    acstate_t k;
    acstate_t *p;
    acstate_t **NextState = acsm->acsmNextState;

    for (k = 0; k < (acstate_t)acsm->acsmNumStates; k++)
    {
        p = (acstate_t *)AC_MALLOC_DFA(acsm->sizeofstate * (acsm->acsmAlphabetSize + 2), acsm->sizeofstate);

        if (p == nullptr)
            return -1;

        List_ConvToFull(acsm, k, (p + 2));
        p[0] = 0;
        p[1] = 0;

        NextState[k] = p;
    }

    return 0;
}

ACSM_STRUCT3 *acsmNew3(const MpseAgent *agent)
{
    ACSM_STRUCT3 *p = (ACSM_STRUCT3 *)AC_MALLOC(sizeof(ACSM_STRUCT3), ACSM3_MEMORY_TYPE__NONE);

    if (p)
    {
        p->agent = agent;
        p->acsmAlphabetSize = 256;

        // OpenCL Context Creation
        std::vector<cl::Platform> platforms;
        std::vector<cl::Device> devices;
        cl::Platform::get(&platforms);
        // if (platforms.size() == 0)
        // {
        //     printf("Error, no OpenCL Platform \n");
        // }
        // else
        // {
        //     std::cout << platforms.front().getInfo<CL_PLATFORM_NAME>() << std::endl;
        // }
        p->platform = platforms.front();
        p->platform.getDevices(CL_DEVICE_TYPE_GPU, &devices);
        // if (devices.size() == 0) {
        //     printf("Error, no OpenCL Device \n");
        // }
        // else
        // {
        //     std::cout << devices.front().getInfo<CL_DEVICE_NAME>() << std::endl;
        // }
        p->device = devices.front();
        p->context = cl::Context(p->device);

        // OpenCL Kernel Creation
        std::ifstream kernel_file("ac_gpu.cl");
        std::string kernel_code(std::istreambuf_iterator<char>(kernel_file), (std::istreambuf_iterator<char>()));
        p->source.push_back({kernel_code.c_str(), kernel_code.length()});

        p->program = cl::Program(p->context, p->source, &p->err);

        if (p->err != CL_SUCCESS)
        {
            printf("Error building : %i \n", p->err);
        }
        p->err = p->program.build("-cl-std=CL2.0");

        // auto status = p->program.getBuildInfo<CL_PROGRAM_BUILD_STATUS>();

        if (p->err != CL_SUCCESS)
        {
            std::cout << p->program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(p->device) << std::endl;
        }

        p->kernel = cl::Kernel(p->program, "ac_gpu", &p->err);

        if (p->err != CL_SUCCESS)
        {
            printf("Error building : %i \n", p->err);
        }

        p->queue = cl::CommandQueue(p->context, p->device, p->err);

        if (p->err != CL_SUCCESS)
        {
            printf("Error building : %i \n", p->err);
        }

        // p->cl_Tx = cl::Buffer(p->context, CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(uint8_t) * MAX_PACKET_SIZE * BUFFER_SIZE);

        // p->cl_n = cl::Buffer(p->context, CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(int) * BUFFER_SIZE);

        // p->tx_map_ptr = (uint8_t *)p->queue.enqueueMapBuffer(p->cl_Tx, CL_TRUE, CL_MAP_WRITE, 0, sizeof(uint8_t) * MAX_PACKET_SIZE * BUFFER_SIZE);

        // p->packet_length_buffer = (int *)p->queue.enqueueMapBuffer(p->cl_n, CL_TRUE, CL_MAP_WRITE, 0, sizeof(int) * BUFFER_SIZE);

        // p->buffer_index = 0;

        // memset(p->packet_length_buffer, 0, sizeof(int) * BUFFER_SIZE);
    }

    return p;
}

int acsmAddPattern3(
    ACSM_STRUCT3 *p, const uint8_t *pat, unsigned n, bool nocase,
    bool negative, void *user)
{
    ACSM_PATTERN3 *plist;

    plist = (ACSM_PATTERN3 *)AC_MALLOC(sizeof(ACSM_PATTERN3), ACSM3_MEMORY_TYPE__PATTERN);

    plist->patrn = (uint8_t *)AC_MALLOC(n, ACSM3_MEMORY_TYPE__PATTERN);

    ConvertCaseEx(plist->patrn, pat, n);

    plist->casepatrn = (uint8_t *)AC_MALLOC(n, ACSM3_MEMORY_TYPE__PATTERN);

    memcpy(plist->casepatrn, pat, n);

    plist->n = n;
    plist->nocase = nocase;
    plist->negative = negative;
    plist->udata = user;

    plist->next = p->acsmPatterns;
    p->acsmPatterns = plist;
    p->numPatterns++;

    return 0;
}

static void acsmUpdateMatchStates(ACSM_STRUCT3 *acsm)
{
    acstate_t state;
    acstate_t **NextState = acsm->acsmNextState;
    ACSM_PATTERN3 **Matchlist = acsm->acsmMatchList;

    for (state = 0; state < (acstate_t)acsm->acsmNumStates; state++)
    {
        acstate_t *p = NextState[state];

        if (Matchlist[state])
        {
            p[1] = 1;

            summary.num_match_states++;
        }
    }
}

static void acsmBuildMatchStateTrees3(SnortConfig *sc, ACSM_STRUCT3 *acsm)
{
    ACSM_PATTERN3 **MatchList = acsm->acsmMatchList;
    ACSM_PATTERN3 *mlist;

    for (int i = 0; i < acsm->acsmNumStates; i++)
    {
        for (mlist = MatchList[i]; mlist != nullptr; mlist = mlist->next)
        {
            if (mlist->udata)
            {
                if (mlist->negative)
                {
                    acsm->agent->negate_list(mlist->udata, &MatchList[i]->neg_list);
                }
                else
                {
                    acsm->agent->build_tree(sc, mlist->udata, &MatchList[i]->rule_option_tree);
                }
            }
        }

        if (MatchList[i])
        {
            acsm->agent->build_tree(sc, nullptr, &MatchList[i]->rule_option_tree);
        }
    }
}

void acsmCompressStates(ACSM_STRUCT3 *acsm, int flag)
{
    if (acsm == nullptr)
        return;
    acsm->compress_states = flag;
}

static inline int _acsmCompile3(ACSM_STRUCT3 *acsm)
{
    ACSM_PATTERN3 *plist;

    for (plist = acsm->acsmPatterns; plist != nullptr; plist = plist->next)
    {
        acsm->acsmMaxStates += plist->n;
    }

    acsm->acsmMaxStates++;

    acsm->acsmTransTable = (trans_node_t **)AC_MALLOC(sizeof(trans_node_t *) * acsm->acsmMaxStates, ACSM3_MEMORY_TYPE__TRANSTABLE);
    acsm->acsmMatchList = (ACSM_PATTERN3 **)AC_MALLOC(sizeof(ACSM_PATTERN3 *) * acsm->acsmMaxStates, ACSM3_MEMORY_TYPE__MATCHLIST);

    // acsm->matchArray = (ACSM_PATTERN3 *)calloc(acsm->acsmMaxStates, sizeof(ACSM_PATTERN3));
    acsm->matchArray = (int *)calloc(acsm->acsmMaxStates, sizeof(int));

    acsm->acsmNumStates = 0;

    for (plist = acsm->acsmPatterns; plist != nullptr; plist = plist->next)
    {
        summary.num_patterns++;
        summary.num_characters += plist->n;
        AddPatternStates(acsm, plist);
    }

    acsm->acsmNumStates++;

    if (acsm->compress_states)
    {
        if (acsm->acsmNumStates < UINT8_MAX)
        {
            acsm->sizeofstate = 1;
            summary.num_1byte_instances++;
        }
        else if (acsm->acsmNumStates < UINT16_MAX)
        {
            acsm->sizeofstate = 2;
            summary.num_2byte_instances++;
        }
        else
        {
            acsm->sizeofstate = 4;
            summary.num_4byte_instances++;
        }
    }
    else
    {
        acsm->sizeofstate = 4;
    }

    acsm->acsmFailState = (acstate_t *)AC_MALLOC(sizeof(acstate_t) * acsm->acsmNumStates, ACSM3_MEMORY_TYPE__FAILSTATE);

    acsm->acsmNextState = (acstate_t **)AC_MALLOC_DFA(sizeof(acstate_t *) * acsm->acsmNumStates, acsm->sizeofstate);

    Build_NFA(acsm);

    Convert_NFA_To_DFA(acsm);

    AC_FREE(acsm->acsmFailState, sizeof(acstate_t) * acsm->acsmNumStates, ACSM3_MEMORY_TYPE__FAILSTATE);

    acsm->acsmFailState = nullptr;

    if (Conv_List_To_Full(acsm))
        return -1;

    acsmUpdateMatchStates(acsm);
    List_FreeTransTable(acsm);

    summary.num_states += acsm->acsmNumStates;
    summary.num_transitions += acsm->acsmNumTrans;
    summary.num_instances++;

    memcpy(&summary.acsm, acsm, sizeof(ACSM_STRUCT3));

    return 0;
}

int acsmCompile3(SnortConfig *sc, ACSM_STRUCT3 *acsm)
{
    if (int rval = _acsmCompile3(acsm))
        return rval;

    if (acsm->agent)
        acsmBuildMatchStateTrees3(sc, acsm);

    acstate_t *p;
    acstate_t **NexState = acsm->acsmNextState;
    acsm->stateArray = new int[acsm->acsmNumStates * 258];

    for (int i = 0; i < acsm->acsmNumStates; i++)
    {
        p = NexState[i];
        if (!p)
            continue;

        for (int j = 0; j < 258; j++)
        {
            acsm->stateArray[(i * 258) + j] = p[j];
        }
    }
    acsm->buffer_size = 0;
    acsm->packet_length_buffer = 0;
    acsm->cl_stateTable = cl::Buffer(acsm->context, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(int) * acsm->acsmNumStates * 258, acsm->stateArray);
    acsm->cl_xlatcase = cl::Buffer(acsm->context, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(uint8_t) * acsm->acsmAlphabetSize, xlatcase);
    acsm->cl_matchTable = cl::Buffer(acsm->context, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(int) * acsm->acsmMaxStates, acsm->matchArray);
    acsm->cl_result = cl::Buffer(acsm->context, CL_MEM_WRITE_ONLY | CL_MEM_HOST_READ_ONLY, sizeof(int) * KERNEL_SIZE);

    return 0;
}

int acsm_search_dfa_gpu(
    ACSM_STRUCT3 *acsm, const uint8_t *Tx, int n, MpseMatch match,
    void *context, int *current_state)
{
    ACSM_PATTERN3 *mlist;
    int nfound = 0;
    acstate_t state;
    ACSM_PATTERN3 **MatchList = acsm->acsmMatchList;

    if (current_state == nullptr)
        return 0;

    state = *current_state;

    if (!acsm->buffer_size && n > 0)
    {
        acsm->buffer_size = 2000000;
        acsm->cl_Tx = cl::Buffer(acsm->context, CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(uint8_t) * acsm->buffer_size);
        acsm->tx_map_ptr = (uint8_t *)acsm->queue.enqueueMapBuffer(acsm->cl_Tx, CL_TRUE, CL_MAP_WRITE, 0, sizeof(uint8_t) * acsm->buffer_size);
    }

    if (acsm->packet_length_buffer < (acsm->buffer_size - 3000) && n > 0)
    {
        memcpy(&(acsm->tx_map_ptr[acsm->packet_length_buffer]), Tx, sizeof(uint8_t) * n);
        acsm->packet_length_buffer += n;
        return 0;
    }

    if (n > 0)
    {
        memcpy(&(acsm->tx_map_ptr[acsm->packet_length_buffer]), Tx, sizeof(uint8_t) * n);
        acsm->packet_length_buffer += n;
    }

    if (!acsm->packet_length_buffer)
    {
        return 0;
    }

    cl::Buffer cl_n = cl::Buffer(acsm->context, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(int *), &acsm->packet_length_buffer, &acsm->err);
    acsm->queue.enqueueUnmapMemObject(acsm->cl_Tx, acsm->tx_map_ptr);

    acsm->kernel.setArg(0, acsm->cl_stateTable);
    acsm->kernel.setArg(1, acsm->cl_matchTable);
    acsm->kernel.setArg(2, acsm->cl_xlatcase);
    acsm->kernel.setArg(3, acsm->cl_Tx);
    acsm->kernel.setArg(4, cl_n);
    acsm->kernel.setArg(5, acsm->cl_result);

    acsm->queue.enqueueNDRangeKernel(acsm->kernel, cl::NullRange, cl::NDRange(KERNEL_SIZE), cl::NDRange(1), NULL, &acsm->search_event);

    acsm->queue.flush();

    acsm->tx_map_ptr = (uint8_t *)acsm->queue.enqueueMapBuffer(acsm->cl_Tx, CL_FALSE, CL_MAP_WRITE, 0, sizeof(uint8_t) * acsm->buffer_size);

    acsm->resultArray = (int *)acsm->queue.enqueueMapBuffer(acsm->cl_result, CL_TRUE, CL_MAP_READ, 0, sizeof(int) * KERNEL_SIZE);

    // acsm->search_event.wait();

    // acsm->queue.finish();

    for (int b = 0; b < KERNEL_SIZE; b++)
    {
        if (acsm->resultArray[b] > 0)
        {
            nfound += acsm->resultArray[b];
            match_packets += 1;
        }
    }
    match_instances += nfound;

    acsm->packet_length_buffer = 0;

    acsm->queue.enqueueUnmapMemObject(acsm->cl_result, acsm->resultArray);

    if (!n)
    {
        acsm->queue.enqueueUnmapMemObject(acsm->cl_result, acsm->resultArray);
        acsm->queue.enqueueUnmapMemObject(acsm->cl_Tx, acsm->tx_map_ptr);
    }

    *current_state = state;
    return nfound;
}

void acsmFree3(ACSM_STRUCT3 *acsm)
{
    int i;
    ACSM_PATTERN3 *mlist, *ilist, *plist;

    for (i = 0; i < acsm->acsmNumStates; i++)
    {
        mlist = acsm->acsmMatchList[i];
        while (mlist)
        {
            ilist = mlist;
            mlist = mlist->next;

            if (ilist->rule_option_tree && acsm->agent)
            {
                acsm->agent->tree_free(&(ilist->rule_option_tree));
            }

            if (ilist->neg_list && acsm->agent)
            {
                acsm->agent->list_free(&(ilist->neg_list));
            }

            AC_FREE(ilist, 0, ACSM3_MEMORY_TYPE__NONE);
        }

        AC_FREE_DFA(acsm->acsmNextState[i], 0, 0);
    }

    for (plist = acsm->acsmPatterns; plist;)
    {
        ACSM_PATTERN3 *tmpPlist = plist->next;
        if ((plist->udata != nullptr) && acsm->agent)
        {
            acsm->agent->user_free(plist->udata);
        }

        AC_FREE(plist->patrn, 0, ACSM3_MEMORY_TYPE__NONE);
        AC_FREE(plist->casepatrn, 0, ACSM3_MEMORY_TYPE__NONE);
        AC_FREE(plist, 0, ACSM3_MEMORY_TYPE__NONE);

        plist = tmpPlist;
    }

    AC_FREE_DFA(acsm->acsmNextState, 0, 0);
    AC_FREE(acsm->acsmFailState, 0, ACSM3_MEMORY_TYPE__NONE);
    AC_FREE(acsm->acsmMatchList, 0, ACSM3_MEMORY_TYPE__NONE);
    AC_FREE(acsm, 0, ACSM3_MEMORY_TYPE__NONE);
}

int acsmPatternCount3(ACSM_STRUCT3 *acsm)
{
    return acsm->numPatterns;
}

static void Print_DFA_MatchList(ACSM_STRUCT3 *acsm, int state)
{
    ACSM_PATTERN3 *mlist;

    for (mlist = acsm->acsmMatchList[state]; mlist; mlist = mlist->next)
    {
        printf("%.*s ", mlist->n, mlist->patrn);
    }
}

static void Print_DFA(ACSM_STRUCT3 *acsm)
{
    int k, i;
    acstate_t *p, state, n, index, nb;
    acstate_t **NextState = acsm->acsmNextState;

    printf("Print DFA - %d active states\n", acsm->acsmNumStates);

    for (k = 0; k < acsm->acsmNumStates; k++)
    {
        p = NextState[k];

        if (!p)
            continue;

        printf("state %3d", k);

        for (i = 0; i < acsm->acsmAlphabetSize; i++)
        {
            state = p[i];

            if (state != 0 && state != ACSM_FAIL_STATE3)
            {
                if (isascii(i) && isprint(i))
                    printf("%3c->%-5d\t", i, state);
                else
                    printf("%3d->%-5d\t", i, state);
            }
        }

        Print_DFA_MatchList(acsm, k);

        printf("\n");
    }
}

int acsmPrintDetailInfo3(ACSM_STRUCT3 *acsm)
{
    Print_DFA(acsm);
    return 0;
}

int acsmPrintSummaryInfo3()
{
    ACSM_STRUCT3 *p = &summary.acsm;

    if (!summary.num_states)
        return 0;

    LogValue("storage format", "Full");
    LogValue("finite automaton", "DFA");
    LogCount("alphabet size", p->acsmAlphabetSize);

    LogCount("instances", summary.num_instances);
    LogCount("patterns", summary.num_patterns);
    LogCount("pattern chars", summary.num_characters);

    LogCount("states", summary.num_states);
    LogCount("transitions", summary.num_transitions);
    LogCount("match states", summary.num_match_states);

    if (!summary.acsm.compress_states)
    {
        LogCount("sizeof state", (int)(sizeof(acstate_t)));
    }
    else
    {
        LogValue("sizeof state", "1, 2, or 4");

        if (summary.num_1byte_instances)
        {
            LogCount("1 byte states", summary.num_1byte_instances);
        }
        if (summary.num_2byte_instances)
        {
            LogCount("2 byte states", summary.num_2byte_instances);
        }
        if (summary.num_4byte_instances)
        {
            LogCount("4 byte states", summary.num_4byte_instances);
        }
    }

    double scale;

    if (acsm3_total_memory < 1024 * 1024)
    {
        scale = 1024;
        LogValue("memory scale", "KB");
    }
    else
    {
        scale = 1024 * 1024;
        LogValue("memory scale", "MB");
    }
    LogStat("total memory", acsm3_total_memory / scale);
    LogStat("pattern memory", acsm3_pattern_memory / scale);
    LogStat("match list memory", acsm3_matchlist_memory / scale);
    LogStat("transition memory", acsm3_transtable_memory / scale);
    LogStat("fail state memory", acsm3_failstate_memory / scale);

    return 0;
}