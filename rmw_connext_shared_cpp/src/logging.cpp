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

#include <rmw/error_handling.h>

#include "rmw_connext_shared_cpp/logging.hpp"

LoggingInfo::LoggingInfo()
{
}

rmw_ret_t LoggingInfo::load(const char * xml_file_path)
{
  m_xmlDocument.LoadFile(xml_file_path);

  auto log_options = m_xmlDocument.FirstChildElement("participant_security_log");
  if (log_options == nullptr) {
    RMW_SET_ERROR_MSG("logger xml file missing 'participant_security_log'");
    return RMW_RET_ERROR;
  }

  auto log_file_options = log_options->FirstChildElement("log_file");
  if (log_file_options != nullptr) {
    m_log_file = log_file_options->GetText();
  }

  auto log_level_options = log_options->FirstChildElement("log_verbosity");
  if (log_level_options != nullptr) {
    m_log_verbosity = log_level_options->GetText();
  }

  auto distribute_options = log_options->FirstChildElement("distribute");
  if (distribute_options != nullptr) {
    auto enable_options = distribute_options->FirstChildElement("enable");
    if (enable_options != nullptr) {
      m_distribute_enable = enable_options->GetText();
    }
  }

  return RMW_RET_OK;
}

const char * LoggingInfo::log_file() const
{
  return m_log_file;
}

const char * LoggingInfo::log_verbosity() const
{
  return m_log_verbosity;
}

const char * LoggingInfo::distribute_enable() const
{
  return m_distribute_enable;
}

DDS::DomainParticipantQos LoggingInfo::distribute_qos() const
{
  return m_distribute_qos;
}
