//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// appid_peg_counts.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_peg_counts.h"

#include <algorithm>
#include <string>

#include "utils/stats.h"

using namespace snort;

std::unordered_map<AppId, uint32_t> AppIdPegCounts::appid_detector_pegs_idx;
std::vector<std::string> AppIdPegCounts::appid_detectors_info;
THREAD_LOCAL std::vector<AppIdPegCounts::AppIdDynamicPeg>* AppIdPegCounts::appid_peg_counts;
AppIdPegCounts::AppIdDynamicPeg AppIdPegCounts::appid_dynamic_sum[SF_APPID_MAX + 1];

void AppIdPegCounts::init_pegs()
{
    AppIdPegCounts::AppIdDynamicPeg zeroed_peg = AppIdPegCounts::AppIdDynamicPeg();
    appid_peg_counts = new std::vector<AppIdPegCounts::AppIdDynamicPeg>(
        appid_detectors_info.size() + 1, zeroed_peg);
}

void AppIdPegCounts::cleanup_pegs()
{
    delete appid_peg_counts;
}

void AppIdPegCounts::cleanup_peg_info()
{
    appid_detectors_info.clear();
    appid_detector_pegs_idx.clear();
}

void AppIdPegCounts::cleanup_dynamic_sum()
{
    if ( !appid_peg_counts )
        return;

    for ( unsigned app_num = 0; app_num < AppIdPegCounts::appid_detectors_info.size(); app_num++ )
    {
        memset(appid_dynamic_sum[app_num].stats, 0, sizeof(PegCount) *
            DetectorPegs::NUM_APPID_DETECTOR_PEGS);
        memset((*appid_peg_counts)[app_num].stats, 0, sizeof(PegCount) *
            DetectorPegs::NUM_APPID_DETECTOR_PEGS);
    }

    // reset unknown_app stats
    memset(appid_dynamic_sum[SF_APPID_MAX].stats, 0, sizeof(PegCount) *
        DetectorPegs::NUM_APPID_DETECTOR_PEGS);
    memset((*appid_peg_counts)[appid_peg_counts->size() - 1].stats, 0, sizeof(PegCount) *
        DetectorPegs::NUM_APPID_DETECTOR_PEGS);
}

void AppIdPegCounts::add_app_peg_info(std::string app_name, AppId app_id)
{
    std::replace(app_name.begin(), app_name.end(), ' ', '_');

    appid_detector_pegs_idx[app_id] = appid_detectors_info.size();
    appid_detectors_info.emplace_back(app_name);
}

void AppIdPegCounts::sum_stats()
{
    if (!appid_peg_counts)
        return;

    const unsigned peg_num = appid_peg_counts->size() ? (appid_peg_counts->size() - 1) : 0;
    const AppIdDynamicPeg* ptr = (AppIdDynamicPeg*)appid_peg_counts->data();

    for ( unsigned i = 0; i < peg_num; ++i )
    {
        for (unsigned j = 0; j < DetectorPegs::NUM_APPID_DETECTOR_PEGS; ++j)
            appid_dynamic_sum[i].stats[j] += ptr[i].stats[j];
    }

    // unknown_app stats
    for (unsigned j = 0; j < DetectorPegs::NUM_APPID_DETECTOR_PEGS; ++j)
        appid_dynamic_sum[SF_APPID_MAX].stats[j] += ptr[peg_num].stats[j];
}

void AppIdPegCounts::inc_service_count(AppId id)
{
    (*appid_peg_counts)[get_stats_index(id)].stats[DetectorPegs::SERVICE_DETECTS]++;
}

void AppIdPegCounts::inc_client_count(AppId id)
{
    (*appid_peg_counts)[get_stats_index(id)].stats[DetectorPegs::CLIENT_DETECTS]++;
}

void AppIdPegCounts::inc_payload_count(AppId id)
{
    (*appid_peg_counts)[get_stats_index(id)].stats[DetectorPegs::PAYLOAD_DETECTS]++;
}

void AppIdPegCounts::inc_user_count(AppId id)
{
    (*appid_peg_counts)[get_stats_index(id)].stats[DetectorPegs::USER_DETECTS]++;
}

void AppIdPegCounts::inc_misc_count(AppId id)
{
    (*appid_peg_counts)[get_stats_index(id)].stats[DetectorPegs::MISC_DETECTS]++;
}

void AppIdPegCounts::inc_referred_count(AppId id)
{
    (*appid_peg_counts)[get_stats_index(id)].stats[DetectorPegs::REFERRED_DETECTS]++;
}

uint32_t AppIdPegCounts::get_stats_index(AppId id)
{
    std::unordered_map<AppId, uint32_t>::iterator stats_idx_it = appid_detector_pegs_idx.find(id);
    if ( stats_idx_it != appid_detector_pegs_idx.end() )
        return stats_idx_it->second;
    else
        return appid_detectors_info.size();
}

void AppIdPegCounts::print()
{
    bool print = false;
    unsigned app_num = AppIdPegCounts::appid_detectors_info.size();

    for (unsigned i = 0; i < app_num; i++)
    {
        AppIdDynamicPeg* pegs = &appid_dynamic_sum[i];
        if (!pegs->all_zeros())
        {
            print = true;
            break;
        }
    }

    AppIdDynamicPeg* unknown_pegs = &appid_dynamic_sum[SF_APPID_MAX];
    if (!print && unknown_pegs->all_zeros())
        return;

    LogLabel("Appid Statistics");
    LogLabel("detected apps and services");

    char buff[120];
    snprintf(buff, sizeof(buff), "%25.25s: %-10s %-10s %-10s %-10s %-10s %-10s",
        "Application", "Services", "Clients", "Users", "Payloads", "Misc", "Referred");
    LogText(buff);

    for (unsigned i = 0; i < app_num; i++)
    {
        AppIdDynamicPeg* pegs = &appid_dynamic_sum[i];
        if (pegs->all_zeros())
            continue;

        std::string app_name = AppIdPegCounts::appid_detectors_info[i];
        pegs->print(app_name.c_str(), buff, sizeof(buff));
        LogText(buff);
    }

    if (!unknown_pegs->all_zeros())
    {
        unknown_pegs->print("unknown", buff, sizeof(buff));
        LogText(buff);
    }
}
