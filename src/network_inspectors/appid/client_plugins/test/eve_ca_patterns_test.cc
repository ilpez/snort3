//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
//
// eve_ca_patterns_test.cc author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client_plugins/eve_ca_patterns.cc"
#include "client_plugins_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

static EveCaPatternMatchers* eve_matcher = nullptr;
EveCaPattern eve_ca(APPID_UT_ID, "firefox", 90);

namespace snort
{
int SearchTool::find_all(const char* pattern, unsigned, MpseMatch, bool, void* data)
{
    if (strcmp(pattern, "firefox") == 0)
        eve_ca_pattern_match(&eve_ca, nullptr, 0, data, nullptr);
    return 0;
}
}

TEST_GROUP(eve_ca_patterns_tests)
{
    void setup() override
    {
        eve_matcher = new EveCaPatternMatchers();
    }
    void teardown() override
    {
        delete eve_matcher;
    }
};


TEST(eve_ca_patterns_tests, eve_ca_pattern_match)
{
    EveCaPatternList data;
    EveCaPattern eve1(APPID_UT_ID + 1, "firefox", 80);
    eve_ca_pattern_match(&eve1, nullptr, 0, &data, nullptr);
    EveCaPattern* eve = data.back();
    CHECK(eve->app_id == eve1.app_id);
    CHECK(eve->pattern == eve1.pattern);
    CHECK(eve->confidence == eve1.confidence);

    EveCaPattern eve2(APPID_UT_ID + 2, "chrome", 95);
    eve_ca_pattern_match(&eve2, nullptr, 0, &data, nullptr);
    eve = data.back();
    CHECK(eve->app_id == eve2.app_id);
    CHECK(eve->pattern == eve2.pattern);
    CHECK(eve->confidence == eve2.confidence);
    CHECK(data.size() == 2);
}


TEST(eve_ca_patterns_tests, match_eve_ca_pattern)
{
    // 1. pattern not present in pattern matcher list
    CHECK(eve_matcher->match_eve_ca_pattern("chrome", 95) == 0);

    // 2. pattern matches, confidence doesn't match
    CHECK(eve_matcher->match_eve_ca_pattern("firefox", 60) == 0);

    // 3. pattern and confidence matches
    CHECK(eve_matcher->match_eve_ca_pattern("firefox", 90) == APPID_UT_ID);

    // 4. pattern matches, reported confidence > existing value
    CHECK(eve_matcher->match_eve_ca_pattern("firefox", 92) == APPID_UT_ID);
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}

