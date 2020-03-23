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

std::string write_logging_xml(const std::string & xml)
{
  char xml_file_path[] = "xml_file_XXXXXX";
  close(mkstemp(xml_file_path));

  std::ofstream xml_file;
  xml_file.open(xml_file_path);
  xml_file << "<?xml version='1.0' encoding='UTF-8'?>" << std::endl;
  xml_file << "<participant_security_log version='1'>" << std::endl;
  xml_file << xml << std::endl;
  xml_file << "</participant_security_log>" << std::endl;
  xml_file.close();

  return xml_file_path;
}

TEST(Logging, test_log_file)
{
  std::string xml_file_path = write_logging_xml("<log_file>foo</log_file>");
  LoggingInfo logging_info;

  ASSERT_EQ(logging_info.load(xml_file_path.c_str()), RMW_RET_OK);
  EXPECT_STREQ(logging_info.log_file(), "foo");
}

TEST(Logging, test_log_level)
{
  std::string xml_file_path = write_logging_xml("<log_verbosity>CRITICAL</log_verbosity>");
  LoggingInfo logging_info;

  ASSERT_EQ(logging_info.load(xml_file_path.c_str()), RMW_RET_OK);
  EXPECT_STREQ(logging_info.log_verbosity(), "CRITICAL");
}

TEST(Logging, test_log_distribute)
{
  std::string xml_file_path = write_logging_xml("<distribute><enable>true</enable></distribute>");
  LoggingInfo logging_info;

  ASSERT_EQ(logging_info.load(xml_file_path.c_str()), RMW_RET_OK);
  EXPECT_STREQ(logging_info.distribute_enable(), "true");
}
