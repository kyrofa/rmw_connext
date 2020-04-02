// Copyright 2020 Canonical Ltd.
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

#ifndef RMW_CONNEXT_SHARED_CPP__LOGGING_HPP_
#define RMW_CONNEXT_SHARED_CPP__LOGGING_HPP_

#include <tinyxml2.h>

#include <rmw/ret_types.h>

#include "rmw_connext_shared_cpp/ndds_include.hpp"

rmw_ret_t apply_logging_configuration_from_file(
  const char * xml_file_path,
  DDS::PropertyQosPolicy & policy);

#endif  // RMW_CONNEXT_SHARED_CPP__LOGGING_HPP_
