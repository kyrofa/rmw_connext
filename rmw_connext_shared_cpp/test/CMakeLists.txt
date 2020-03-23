find_package(ament_cmake_gtest REQUIRED)

ament_add_gtest(test_rmw_connext_shared_cpp
    test_topic_cache.cpp
    test_logging_xml.cpp)

if(TARGET test_rmw_connext_shared_cpp)
    ament_target_dependencies(test_rmw_connext_shared_cpp)
    target_link_libraries(test_rmw_connext_shared_cpp ${PROJECT_NAME})
endif()
