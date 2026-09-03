cmake_minimum_required(VERSION 3.16)

project(t32perf_target_sdk VERSION 0.1.0 LANGUAGES C)

option(T32PERF_ENABLE "Enable target event emission" ON)
option(T32PERF_BUILD_TESTS "Build the target SDK tests" ON)

add_library(t32perf_target STATIC
    src/event.c
    src/transports.c
)
add_library(t32perf::target ALIAS t32perf_target)

target_include_directories(t32perf_target
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(t32perf_target PUBLIC c_std_99)
set_target_properties(t32perf_target PROPERTIES
    C_EXTENSIONS OFF
    EXPORT_NAME target
    OUTPUT_NAME t32perf_target
)

if(T32PERF_ENABLE)
    target_compile_definitions(t32perf_target PUBLIC T32PERF_ENABLE=1)
else()
    target_compile_definitions(t32perf_target PUBLIC T32PERF_ENABLE=0)
endif()

if(MSVC)
    target_compile_options(t32perf_target PRIVATE /W4 /WX)
else()
    target_compile_options(t32perf_target PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

if(T32PERF_BUILD_TESTS)
    enable_testing()

    if(T32PERF_ENABLE)
        add_executable(t32perf_target_tests tests/test_event.c)
        target_link_libraries(t32perf_target_tests PRIVATE t32perf::target)
        target_compile_features(t32perf_target_tests PRIVATE c_std_99)
        set_target_properties(t32perf_target_tests PROPERTIES C_EXTENSIONS OFF)
        if(MSVC)
            target_compile_options(t32perf_target_tests PRIVATE /W4 /WX)
        else()
            target_compile_options(
                t32perf_target_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
        endif()
        add_test(NAME t32perf_target_tests COMMAND t32perf_target_tests)
    endif()

    add_executable(t32perf_target_disabled_tests tests/test_disabled.c)
    target_include_directories(
        t32perf_target_disabled_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_features(t32perf_target_disabled_tests PRIVATE c_std_99)
    set_target_properties(t32perf_target_disabled_tests PROPERTIES C_EXTENSIONS OFF)
    if(MSVC)
        target_compile_options(t32perf_target_disabled_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(
            t32perf_target_disabled_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(
        NAME t32perf_target_disabled_tests COMMAND t32perf_target_disabled_tests)
endif()

include(GNUInstallDirs)
install(TARGETS t32perf_target
    EXPORT t32perfTargetSdkTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT t32perfTargetSdkTargets
    FILE t32perfTargetSdkTargets.cmake
    NAMESPACE t32perf::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/t32perfTargetSdk
)
