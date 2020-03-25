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

namespace
{
rmw_ret_t apply_property(
  DDS::PropertyQosPolicy & policy, const char * const property,
  const tinyxml2::XMLElement & element, const char * const tag_name)
{
  auto tag = element.FirstChildElement(tag_name);
  if (tag != nullptr) {
    const char * depth = tag->GetText();
    if (depth == nullptr) {
      RMW_SET_ERROR_MSG_WITH_FORMAT_STRING(
        "failed to set security logging %s: improper format",
        tag_name);
      return RMW_RET_ERROR;
    }

    auto status = DDS::PropertyQosPolicyHelper::add_property(
      policy,
      property,
      depth,
      DDS::BOOLEAN_FALSE);
    if (status != DDS::RETCODE_OK) {
      RMW_SET_ERROR_MSG_WITH_FORMAT_STRING("failed to set security logging %s", tag_name);
      return RMW_RET_ERROR;
    }
  }

  return RMW_RET_OK;
}
}  // namespace

rmw_ret_t apply_logging_configuration_from_file(
  const char * xml_file_path,
  DDS::PropertyQosPolicy & policy)
{
  tinyxml2::XMLDocument document;
  document.LoadFile(xml_file_path);

  auto log_options = document.FirstChildElement("security_log");
  if (log_options == nullptr) {
    RMW_SET_ERROR_MSG("logger xml file missing 'security_log'");
    return RMW_RET_ERROR;
  }

  auto status = apply_property(
    policy,
    "com.rti.serv.secure.logging.log_file",
    *log_options,
    "file");
  if (status != RMW_RET_OK) {
    return status;
  }

  status = apply_property(
    policy,
    "com.rti.serv.secure.logging.verbosity",
    *log_options,
    "verbosity");
  if (status != RMW_RET_OK) {
    return status;
  }

  status = apply_property(
    policy,
    "com.rti.serv.secure.logging.distribute.enable",
    *log_options,
    "distribute");
  if (status != RMW_RET_OK) {
    return status;
  }

  auto qos_options = log_options->FirstChildElement("qos");
  if (qos_options != nullptr) {
    status = apply_property(
      policy,
      "com.rti.serv.secure.logging.distribute.writer_history_depth",
      *qos_options,
      "depth");
    if (status != RMW_RET_OK) {
      return status;
    }
  }

  return RMW_RET_OK;
}
