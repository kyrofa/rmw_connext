// Copyright 2020 Canonical Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <fstream>
#include <string>

#include "rmw_connext_shared_cpp/logging.hpp"

#include "gtest/gtest.h"

namespace
{
const char * const log_file_property_name = "com.rti.serv.secure.logging.log_file";
const char * const verbosity_property_name = "com.rti.serv.secure.logging.verbosity";
const char * const distribute_enable_property_name =
  "com.rti.serv.secure.logging.distribute.enable";
const char * const distribute_depth_property_name =
  "com.rti.serv.secure.logging.distribute.writer_history_depth";

std::string write_logging_xml(const std::string & xml)
{
  // mkstemp isn't cross-platform, and we don't care about security here
  char * xml_file_path = std::tmpnam(nullptr);

  std::ofstream xml_file;
  xml_file.open(xml_file_path);
  xml_file << "<?xml version='1.0' encoding='UTF-8'?>" << std::endl;
  xml_file << "<security_log version='1'>" << std::endl;
  xml_file << xml << std::endl;
  xml_file << "</security_log>" << std::endl;
  xml_file.close();

  return xml_file_path;
}

const char * lookup_property_value(DDS::PropertyQosPolicy & policy, const char * property_name)
{
  auto property = DDS::PropertyQosPolicyHelper::lookup_property(
    policy,
    property_name);

  if (property == nullptr) {
    return nullptr;
  }

  return property->value;
}

const char * log_file_property(DDS::PropertyQosPolicy & policy)
{
  return lookup_property_value(policy, log_file_property_name);
}

const char * verbosity_property(DDS::PropertyQosPolicy & policy)
{
  return lookup_property_value(policy, verbosity_property_name);
}

const char * logging_distribute_enable_property(DDS::PropertyQosPolicy & policy)
{
  return lookup_property_value(policy, distribute_enable_property_name);
}

const char * logging_distribute_depth_property(DDS::PropertyQosPolicy & policy)
{
  return lookup_property_value(policy, distribute_depth_property_name);
}
}  // namespace

TEST(Logging, test_log_file)
{
  std::string xml_file_path = write_logging_xml("<file>foo</file>");
  DDS::PropertyQosPolicy policy;
  ASSERT_EQ(apply_logging_configuration_from_file(xml_file_path.c_str(), policy), RMW_RET_OK);

  EXPECT_STREQ(log_file_property(policy), "foo");
  EXPECT_EQ(verbosity_property(policy), nullptr);
  EXPECT_EQ(logging_distribute_enable_property(policy), nullptr);
  EXPECT_EQ(logging_distribute_depth_property(policy), nullptr);
}

TEST(Logging, test_log_verbosity)
{
  std::string xml_file_path = write_logging_xml("<verbosity>CRITICAL</verbosity>");
  DDS::PropertyQosPolicy policy;
  ASSERT_EQ(apply_logging_configuration_from_file(xml_file_path.c_str(), policy), RMW_RET_OK);

  EXPECT_EQ(log_file_property(policy), nullptr);
  EXPECT_STREQ(verbosity_property(policy), "CRITICAL");
  EXPECT_EQ(logging_distribute_enable_property(policy), nullptr);
  EXPECT_EQ(logging_distribute_depth_property(policy), nullptr);
}

TEST(Logging, test_log_distribute)
{
  std::string xml_file_path = write_logging_xml("<distribute>true</distribute>");
  DDS::PropertyQosPolicy policy;
  ASSERT_EQ(apply_logging_configuration_from_file(xml_file_path.c_str(), policy), RMW_RET_OK);

  EXPECT_EQ(log_file_property(policy), nullptr);
  EXPECT_EQ(verbosity_property(policy), nullptr);
  EXPECT_STREQ(logging_distribute_enable_property(policy), "true");
  EXPECT_EQ(logging_distribute_depth_property(policy), nullptr);
}

TEST(Logging, test_log_depth)
{
  std::string xml_file_path = write_logging_xml("<qos><depth>10</depth></qos>");
  DDS::PropertyQosPolicy policy;
  ASSERT_EQ(apply_logging_configuration_from_file(xml_file_path.c_str(), policy), RMW_RET_OK);

  EXPECT_EQ(log_file_property(policy), nullptr);
  EXPECT_EQ(verbosity_property(policy), nullptr);
  EXPECT_EQ(logging_distribute_enable_property(policy), nullptr);
  EXPECT_STREQ(logging_distribute_depth_property(policy), "10");
}

TEST(Logging, test_profile)
{
  std::string xml_file_path = write_logging_xml("<qos><profile>DEFAULT</profile></qos>");
  DDS::PropertyQosPolicy policy;
  ASSERT_EQ(apply_logging_configuration_from_file(xml_file_path.c_str(), policy), RMW_RET_OK);

  EXPECT_EQ(log_file_property(policy), nullptr);
  EXPECT_EQ(verbosity_property(policy), nullptr);
  EXPECT_EQ(logging_distribute_enable_property(policy), nullptr);
  EXPECT_STREQ(logging_distribute_depth_property(policy), "10");
}

TEST(Logging, test_profile_overwrite)
{
  std::string xml_file_path = write_logging_xml(
    "<qos>\n"
    "  <profile>DEFAULT</profile>\n"
    "  <depth>42</depth>\n"
    "</qos>");
  DDS::PropertyQosPolicy policy;
  ASSERT_EQ(apply_logging_configuration_from_file(xml_file_path.c_str(), policy), RMW_RET_OK);

  EXPECT_EQ(log_file_property(policy), nullptr);
  EXPECT_EQ(verbosity_property(policy), nullptr);
  EXPECT_EQ(logging_distribute_enable_property(policy), nullptr);
  EXPECT_STREQ(logging_distribute_depth_property(policy), "42");
}

TEST(Logging, test_profile_invalid)
{
  std::string xml_file_path = write_logging_xml("<qos><profile>INVALID_PROFILE</profile></qos>");
  DDS::PropertyQosPolicy policy;
  ASSERT_EQ(apply_logging_configuration_from_file(xml_file_path.c_str(), policy), RMW_RET_ERROR);
}

TEST(Logging, test_all)
{
  std::string xml_file_path = write_logging_xml(
    "<file>foo</file>\n"
    "<verbosity>CRITICAL</verbosity>\n"
    "<distribute>true</distribute>\n"
    "<qos>\n"
    "  <depth>10</depth>\n"
    "</qos>");
  DDS::PropertyQosPolicy policy;
  ASSERT_EQ(apply_logging_configuration_from_file(xml_file_path.c_str(), policy), RMW_RET_OK);

  EXPECT_STREQ(log_file_property(policy), "foo");
  EXPECT_STREQ(verbosity_property(policy), "CRITICAL");
  EXPECT_STREQ(logging_distribute_enable_property(policy), "true");
  EXPECT_STREQ(logging_distribute_depth_property(policy), "10");
}
