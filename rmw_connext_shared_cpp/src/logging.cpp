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

#include <rcutils/snprintf.h>
#include <rmw/error_handling.h>
#include <rmw/qos_profiles.h>
#include <rmw/types.h>

#include "rmw_connext_shared_cpp/logging.hpp"

namespace
{
const char * const log_file_property_name = "com.rti.serv.secure.logging.log_file";
const char * const verbosity_property_name = "com.rti.serv.secure.logging.verbosity";
const char * const distribute_enable_property_name =
  "com.rti.serv.secure.logging.distribute.enable";
const char * const distribute_depth_property_name =
  "com.rti.serv.secure.logging.distribute.writer_history_depth";

const struct
{
  const char * const name;
  rmw_qos_profile_t profile;
} supported_profiles[] =
{
  {"SENSOR_DATA", rmw_qos_profile_sensor_data},
  {"PARAMETERS", rmw_qos_profile_parameters},
  {"DEFAULT", rmw_qos_profile_default},
  {"SERVICES_DEFAULT", rmw_qos_profile_services_default},
  {"PARAMETER_EVENTS", rmw_qos_profile_parameter_events},
  {"SYSTEM_DEFAULT", rmw_qos_profile_system_default},
};

rmw_ret_t string_to_rmw_qos_profile(const char * str, rmw_qos_profile_t & profile)
{
  for (const auto & item : supported_profiles) {
    if (strcmp(str, item.name) == 0) {
      profile = item.profile;
      return RMW_RET_OK;
    }
  }

  return RMW_RET_ERROR;
}

rmw_ret_t apply_property(
  DDS::PropertyQosPolicy & policy, const char * const property_name,
  const char * const human_readable_property_name, const char * const value)
{
  // Overwrite existing properties, so remove it if it already exists
  DDS::PropertyQosPolicyHelper::remove_property(policy, property_name);

  auto status = DDS::PropertyQosPolicyHelper::add_property(
    policy,
    property_name,
    value,
    DDS::BOOLEAN_FALSE);
  if (status != DDS::RETCODE_OK) {
    RMW_SET_ERROR_MSG_WITH_FORMAT_STRING(
      "failed to set security logging %s",
      human_readable_property_name);
    return RMW_RET_ERROR;
  }

  return RMW_RET_OK;
}

rmw_ret_t apply_property_from_element(
  DDS::PropertyQosPolicy & policy, const char * const property_name,
  const tinyxml2::XMLElement & element, const char * const tag_name)
{
  auto tag = element.FirstChildElement(tag_name);
  if (tag != nullptr) {
    const char * text = tag->GetText();
    if (text == nullptr) {
      RMW_SET_ERROR_MSG_WITH_FORMAT_STRING(
        "failed to set security logging %s: improper format",
        tag_name);
      return RMW_RET_ERROR;
    }

    return apply_property(policy, property_name, tag_name, text);
  }

  return RMW_RET_OK;
}

rmw_ret_t apply_qos_profile(DDS::PropertyQosPolicy & policy, const rmw_qos_profile_t & profile)
{
  char depth_str[256];
  int max_length = sizeof(depth_str);
  int resulting_length = rcutils_snprintf(depth_str, max_length, "%zu", profile.depth);
  if (resulting_length < 0 || resulting_length > max_length) {
    RMW_SET_ERROR_MSG_WITH_FORMAT_STRING(
      "failed to set security logging depth from profile: unable to convert %zu to string",
      profile.depth);
    return RMW_RET_ERROR;
  }

  return apply_property(policy, distribute_depth_property_name, "depth", depth_str);
}
}  // namespace

rmw_ret_t apply_logging_configuration_from_file(
  const char * xml_file_path,
  DDS::PropertyQosPolicy & policy)
{
  tinyxml2::XMLDocument document;
  document.LoadFile(xml_file_path);

  auto log_element = document.FirstChildElement("security_log");
  if (log_element == nullptr) {
    RMW_SET_ERROR_MSG("logger xml file missing 'security_log'");
    return RMW_RET_ERROR;
  }

  auto status = apply_property_from_element(
    policy,
    log_file_property_name,
    *log_element,
    "file");
  if (status != RMW_RET_OK) {
    return status;
  }

  status = apply_property_from_element(
    policy,
    verbosity_property_name,
    *log_element,
    "verbosity");
  if (status != RMW_RET_OK) {
    return status;
  }

  status = apply_property_from_element(
    policy,
    distribute_enable_property_name,
    *log_element,
    "distribute");
  if (status != RMW_RET_OK) {
    return status;
  }

  auto qos_element = log_element->FirstChildElement("qos");
  if (qos_element != nullptr) {
    // First thing we need to do is apply any QoS profile that was specified.
    // Once that has happened, further settings can be applied to customize.
    auto profile_element = qos_element->FirstChildElement("profile");
    if (profile_element != nullptr) {
      const char * profile_str = profile_element->GetText();
      if (profile_str == nullptr) {
        RMW_SET_ERROR_MSG("failed to set security logging profile: improper format");
        return RMW_RET_ERROR;
      }

      rmw_qos_profile_t profile;
      if (string_to_rmw_qos_profile(profile_str, profile) != RMW_RET_OK) {
        RMW_SET_ERROR_MSG_WITH_FORMAT_STRING(
          "failed to set security logging profile: %s is not a supported profile",
          profile_str);
        return RMW_RET_ERROR;
      }

      status = apply_qos_profile(policy, profile);
      if (status != RMW_RET_OK) {
        return status;
      }
    }

    status = apply_property_from_element(
      policy,
      distribute_depth_property_name,
      *qos_element,
      "depth");
    if (status != RMW_RET_OK) {
      return status;
    }
  }

  return RMW_RET_OK;
}
