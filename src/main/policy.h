//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifndef SNORT_POLICY_H
#define SNORT_POLICY_H

// the following policy types are defined:
//
// -- network - for packet handling
// -- inspection - for flow handling
// -- ips - for rule handling

#ifdef HAVE_UUID
#include <uuid.h>
#else
typedef unsigned char uuid_t[16];
#endif

#include <algorithm>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

#include "framework/data_bus.h"

namespace snort
{
class FilePolicyBase;
class GHash;
class IpsAction;
class PolicySelector;
struct SnortConfig;
}

struct _daq_pkt_hdr;
struct PortTable;
struct vartable_t;
struct sfip_var_t;

typedef unsigned int PolicyId;
typedef snort::GHash PortVarTable;

enum PolicyMode
{
    POLICY_MODE__PASSIVE,
    POLICY_MODE__INLINE,
    POLICY_MODE__INLINE_TEST,
    POLICY_MODE__MAX
};

// FIXIT-L split into separate headers

//-------------------------------------------------------------------------
// traffic stuff
//-------------------------------------------------------------------------

enum ChecksumFlag
{
    CHECKSUM_FLAG__IP   = 0x00000001,
    CHECKSUM_FLAG__TCP  = 0x00000002,
    CHECKSUM_FLAG__UDP  = 0x00000004,
    CHECKSUM_FLAG__ICMP = 0x00000008,
    CHECKSUM_FLAG__ALL  = 0x0000000f,
    CHECKSUM_FLAG__DEF  = 0x80000000
};

enum DecodeEventFlag
{
    DECODE_EVENT_FLAG__DEFAULT = 0x00000001
};

// Snort ac-split creates the nap (network analysis policy)
// Snort++ breaks the nap into network and inspection

class FilePolicy;
class FileRule;

struct NetworkPolicy
{
public:
    NetworkPolicy(PolicyId = 0, PolicyId default_inspection_id = 0);
    NetworkPolicy(NetworkPolicy*, const char*);
    ~NetworkPolicy();

    void add_file_policy_rule(FileRule& file_rule);
    snort::FilePolicyBase* get_base_file_policy() const;
    FilePolicy* get_file_policy() const;

    bool checksum_drops(uint16_t codec_cksum_err_flag)
    { return (checksum_drop & codec_cksum_err_flag) != 0; }

    bool ip_checksums()
    { return (checksum_eval & CHECKSUM_FLAG__IP) != 0; }

    bool udp_checksums()
    { return (checksum_eval & CHECKSUM_FLAG__UDP) != 0; }

    bool tcp_checksums()
    { return (checksum_eval & CHECKSUM_FLAG__TCP) != 0; }

    bool icmp_checksums()
    { return (checksum_eval & CHECKSUM_FLAG__ICMP) != 0; }

protected:
    FilePolicy* file_policy;

public:
    struct TrafficPolicy* traffic_policy;
    snort::DataBus dbus;

    PolicyId policy_id = 0;
    uint32_t user_policy_id = 0;
    PolicyId default_inspection_policy_id = 0;

    // minimum possible (allows all but errors to pass by default)
    uint8_t min_ttl = 1;
    uint8_t new_ttl = 5;

    uint32_t checksum_eval = CHECKSUM_FLAG__ALL | CHECKSUM_FLAG__DEF;
    uint32_t checksum_drop = CHECKSUM_FLAG__DEF;
    uint32_t normal_mask = 0;
    bool cloned = false;

private:
    void init(NetworkPolicy*, const char*);
};

//-------------------------------------------------------------------------
// inspection stuff
//-------------------------------------------------------------------------

struct InspectionPolicy
{
public:
    InspectionPolicy(PolicyId = 0);
    InspectionPolicy(InspectionPolicy* old_inspection_policy);
    ~InspectionPolicy();

    void configure();

public:
    PolicyId policy_id = 0;
    PolicyMode policy_mode = POLICY_MODE__MAX;
    uint32_t user_policy_id = 0;
    uuid_t uuid{};

    struct FrameworkPolicy* framework_policy;
    snort::DataBus dbus;
    bool cloned;

private:
    void init(InspectionPolicy* old_inspection_policy);
};

//-------------------------------------------------------------------------
// detection stuff
//-------------------------------------------------------------------------

struct IpsPolicy
{
public:
    enum Enable : uint8_t { DISABLED, ENABLED, INHERIT_ENABLE };

    IpsPolicy(PolicyId = 0);
    ~IpsPolicy();

public:
    PolicyId policy_id;
    uint32_t user_policy_id = 0;
    uuid_t uuid{};

    PolicyMode policy_mode = POLICY_MODE__MAX;
    bool enable_builtin_rules;
    int rules_loaded = 0;
    int rules_shared = 0;

    std::string includer;
    std::string include;

    std::string rules;
    std::string states;

    uint32_t var_id;

    struct VarEntry* var_table;
    vartable_t* ip_vartable;

    /* The portobjects in these are attached to rtns and used during runtime */
    PortVarTable* portVarTable;     /* named entries, uses a hash table */
    PortTable* nonamePortVarTable;  /* un-named entries */

    Enable default_rule_state = INHERIT_ENABLE;

    bool obfuscate_pii;

    std::string action_override;
    std::map<std::string, std::string> action_map;

    // Holds all plugin actions associated with this policy
    std::vector<snort::IpsAction*> action;
};

//-------------------------------------------------------------------------
// binding stuff
//-------------------------------------------------------------------------

class Shell;

struct PolicyTuple
{
    InspectionPolicy* inspection = nullptr;
    IpsPolicy* ips = nullptr;
    NetworkPolicy* network = nullptr;

    PolicyTuple(InspectionPolicy* ins_pol, IpsPolicy* ips_pol, NetworkPolicy* net_pol) :
        inspection(ins_pol), ips(ips_pol), network(net_pol) { }
};

struct GlobalInspectorPolicy;
class SingleInstanceInspectorPolicy;

class PolicyMap
{
public:
    PolicyMap(PolicyMap* old_map = nullptr, const char* exclude_name = nullptr);
    ~PolicyMap();

    InspectionPolicy* add_inspection_shell(Shell*);
    IpsPolicy* add_ips_shell(Shell*);
    std::shared_ptr<PolicyTuple> add_shell(Shell*, bool include_network);
    std::shared_ptr<PolicyTuple> get_policies(Shell* sh);
    void clone(PolicyMap *old_map, const char* exclude_name);

    Shell* get_shell(unsigned i = 0)
    { return i < shells.size() ? shells[i] : nullptr; }

    void set_user_network(NetworkPolicy* p)
    { user_network[p->user_policy_id] = p; }

    void set_user_inspection(InspectionPolicy* p)
    { user_inspection[p->user_policy_id] = p; }

    void set_user_ips(IpsPolicy* p)
    { user_ips[p->user_policy_id] = p; }

    NetworkPolicy* get_user_network(unsigned user_id)
    {
        auto it = user_network.find(user_id);
        return it == user_network.end() ? nullptr : it->second;
    }

    InspectionPolicy* get_user_inspection(unsigned user_id)
    {
        auto it = user_inspection.find(user_id);
        return it == user_inspection.end() ? nullptr : it->second;
    }

    IpsPolicy* get_user_ips(unsigned user_id)
    {
        auto it = user_ips.find(user_id);
        return it == user_ips.end() ? nullptr : it->second;
    }

    NetworkPolicy* get_network_policy(unsigned i = 0)
    { return i < network_policy.size() ? network_policy[i] : nullptr; }

    InspectionPolicy* get_inspection_policy(unsigned i = 0)
    { return i < inspection_policy.size() ? inspection_policy[i] : nullptr; }

    IpsPolicy* get_ips_policy(unsigned i = 0)
    { return i < ips_policy.size() ? ips_policy[i] : nullptr; }

    IpsPolicy* get_empty_ips()
    { return empty_ips_policy; }

    unsigned network_policy_count()
    { return network_policy.size(); }

    unsigned inspection_policy_count()
    { return inspection_policy.size(); }

    unsigned ips_policy_count()
    { return ips_policy.size(); }

    unsigned shells_count()
    { return shells.size(); }

    void set_cloned(bool state)
    { cloned = state; }

    snort::PolicySelector* get_policy_selector() const
    { return selector; }

    void set_policy_selector(snort::PolicySelector* new_selector)
    { selector = new_selector; }

    SingleInstanceInspectorPolicy* get_file_id()
    { return file_id; }

    SingleInstanceInspectorPolicy* get_flow_tracking()
    { return flow_tracking; }

    GlobalInspectorPolicy* get_global_inspector_policy()
    { return global_inspector_policy; }

    const Shell* get_shell_by_policy(unsigned id) const
    {
        auto it = std::find_if(std::begin(shell_map), std::end(shell_map),
            [=](auto&& p) { return p.second->ips and p.second->ips->policy_id == id; });

        return (it == std::end(shell_map)) ? nullptr : it->first;
    }

private:
    std::vector<Shell*> shells;
    std::vector<InspectionPolicy*> inspection_policy;
    std::vector<IpsPolicy*> ips_policy;
    std::vector<NetworkPolicy*> network_policy;

    IpsPolicy* empty_ips_policy;

    std::unordered_map<Shell*, std::shared_ptr<PolicyTuple>> shell_map;
    std::unordered_map<unsigned, NetworkPolicy*> user_network;
    std::unordered_map<unsigned, InspectionPolicy*> user_inspection;
    std::unordered_map<unsigned, IpsPolicy*> user_ips;

    snort::PolicySelector* selector = nullptr;
    SingleInstanceInspectorPolicy* file_id;
    SingleInstanceInspectorPolicy* flow_tracking;
    GlobalInspectorPolicy* global_inspector_policy;

    bool cloned = false;
};

//-------------------------------------------------------------------------
// navigator stuff
//-------------------------------------------------------------------------

// FIXIT-L may be inlined at some point; on lockdown for now
// FIXIT-L SO_PUBLIC required because SnortConfig::inline_mode(), etc. uses the function
namespace snort
{
SO_PUBLIC NetworkPolicy* get_network_policy();
SO_PUBLIC InspectionPolicy* get_inspection_policy();
SO_PUBLIC IpsPolicy* get_ips_policy();

SO_PUBLIC void set_network_policy(NetworkPolicy*);
SO_PUBLIC void set_inspection_policy(InspectionPolicy*);
SO_PUBLIC void set_ips_policy(IpsPolicy*);

SO_PUBLIC NetworkPolicy* get_default_network_policy(const snort::SnortConfig*);
SO_PUBLIC InspectionPolicy* get_user_inspection_policy(const snort::SnortConfig*, unsigned policy_id);
SO_PUBLIC InspectionPolicy* get_default_inspection_policy(const snort::SnortConfig*);

SO_PUBLIC IpsPolicy* get_ips_policy(const snort::SnortConfig*, unsigned i = 0);
SO_PUBLIC IpsPolicy* get_user_ips_policy(const snort::SnortConfig*, unsigned policy_id);
SO_PUBLIC IpsPolicy* get_empty_ips_policy(const snort::SnortConfig*);
}

void set_network_policy(const snort::SnortConfig*, unsigned = 0);
void set_inspection_policy(const snort::SnortConfig*, unsigned = 0);
void set_ips_policy(const snort::SnortConfig*, unsigned = 0);

void set_policies(const snort::SnortConfig*, Shell*);
void set_default_policy(const snort::SnortConfig*);
void select_default_policy(const _daq_pkt_hdr*, const snort::SnortConfig*);

bool only_inspection_policy();
bool only_ips_policy();

#endif

