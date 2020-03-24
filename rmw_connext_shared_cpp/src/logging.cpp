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

#include <tinyxml2.h>

#include <rmw/error_handling.h>

#include "rmw_connext_shared_cpp/logging.hpp"

rmw_ret_t apply_logging_configuration_from_file(
  const char * xml_file_path,
  DDS::PropertyQosPolicy & policy)
{
  tinyxml2::XMLDocument document;
  document.LoadFile(xml_file_path);

  auto log_options = document.FirstChildElement("participant_security_log");
  if (log_options == nullptr) {
    RMW_SET_ERROR_MSG("logger xml file missing 'participant_security_log'");
    return RMW_RET_ERROR;
  }

  auto log_file_options = log_options->FirstChildElement("log_file");
  if (log_file_options != nullptr) {
    const char * log_file = log_file_options->GetText();
    if (log_file != nullptr) {
      auto status = DDS::PropertyQosPolicyHelper::add_property(
        policy,
        "com.rti.serv.secure.logging.log_file",
        log_file,
        DDS::BOOLEAN_FALSE);
      if (status != DDS::RETCODE_OK) {
        RMW_SET_ERROR_MSG("failed to set security log file");
        return RMW_RET_ERROR;
      }
    }
  }

  auto log_level_options = log_options->FirstChildElement("log_verbosity");
  if (log_level_options != nullptr) {
    const char * log_verbosity = log_level_options->GetText();
    if (log_verbosity != nullptr) {
      auto status = DDS::PropertyQosPolicyHelper::add_property(
        policy,
        "com.rti.serv.secure.logging.verbosity",
        log_verbosity,
        DDS::BOOLEAN_FALSE);
      if (status != DDS::RETCODE_OK) {
        RMW_SET_ERROR_MSG("failed to set security log verbosity");
        return RMW_RET_ERROR;
      }
    }
  }

  auto distribute_options = log_options->FirstChildElement("distribute");
  if (distribute_options != nullptr) {
    auto enable_options = distribute_options->FirstChildElement("enable");
    if (enable_options != nullptr) {
      const char * distribute_enable = enable_options->GetText();
      if (distribute_enable != nullptr) {
        auto status = DDS::PropertyQosPolicyHelper::add_property(
          policy,
          "com.rti.serv.secure.logging.distribute.enable",
          distribute_enable,
          DDS::BOOLEAN_FALSE);
        if (status != DDS::RETCODE_OK) {
          RMW_SET_ERROR_MSG("failed to set security log distribute enable");
          return RMW_RET_ERROR;
        }
      }
    }
  }

  return RMW_RET_OK;
}
