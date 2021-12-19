#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/mpse.h"

#include "acsmx3.h"

using namespace snort;

// "ac_gpu"

class AcgMpse : public Mpse
{
private:
    ACSM_STRUCT3 *obj;

public:
    AcgMpse(const MpseAgent *agent) : Mpse("ac_gpu")
    {
        obj = acsmNew3(agent);
    }

    ~AcgMpse() override
    {
        acsmFree3(obj);
    }

    void set_opt(int flag) override
    {
        acsmCompressStates(obj, 0);
    }

    int add_pattern(
        const uint8_t *P, unsigned m,
        const PatternDescriptor &desc, void *user) override
    {
        return acsmAddPattern3(obj, P, m, desc.no_case, desc.negated, user);
    }

    int prep_patterns(SnortConfig *sc) override
    {
        return acsmCompile3(sc, obj);
    }

    int _search(
        const uint8_t *T, int n, MpseMatch match, void *context, int *current_state) override
    {
        return acsm_search_dfa_gpu(obj, T, n, match, context, current_state);
    }

    int search_all(
        const uint8_t *T, int n, MpseMatch match, void *context, int *current_state) override
    {
        return acsm_search_dfa_gpu(obj, T, n, match, context, current_state);
    }

    int print_info() override
    {
        return acsmPrintDetailInfo3(obj);
    }

    int get_pattern_count() const override
    {
        return acsmPatternCount3(obj);
    }
};

// api

static Mpse *acg_ctor(
    const SnortConfig *, class Module *, const MpseAgent *agent)
{
    return new AcgMpse(agent);
}

static void acg_dtor(Mpse *p)
{
    delete p;
}

static void acg_init()
{
    acsmx3_init_xlatcase();
    acsm3_init_summary();
}

static void acg_print()
{
    acsmPrintSummaryInfo3();
}

static const MpseApi acg_api =
    {
        {PT_SEARCH_ENGINE,
         sizeof(MpseApi),
         SEAPI_VERSION,
         0,
         API_RESERVED,
         API_OPTIONS,
         "ac_gpu",
         "Aho_Corasick Full on GPU with OpenCL",
         nullptr,
         nullptr},
        MPSE_BASE,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        acg_ctor,
        acg_dtor,
        acg_init,
        acg_print,
        nullptr,
};

const BaseApi *se_ac_gpu[] =
    {
        &acg_api.base,
        nullptr};