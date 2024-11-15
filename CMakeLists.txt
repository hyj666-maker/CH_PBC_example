cmake_minimum_required(VERSION 3.0)
project(DCH)

set(CMAKE_CXX_STANDARD 17)
SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_BUILD_TYPE "Release")

find_package(OpenSSL REQUIRED)
include_directories(include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -pthread -mavx2 -O3")
add_compile_options(-Wunknown-pragmas)

FIND_PACKAGE(OpenMP REQUIRED)
if (OPENMP_FOUND)
    message("OPENMP FOUND")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif ()

if (ENABLE_OMP)
    message("OpenMP enabled")
    add_definitions("-DParallel")
endif (ENABLE_OMP)

if (LOCAL_DEBUG)
    message("LOCAL_DEBUG enabled")
    add_definitions("-DDEBUG")
endif (LOCAL_DEBUG)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS}")

link_libraries(gmp pbc OpenSSL::SSL)

add_executable(CH_ET_test src/scheme/CH_ET.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/CH_ET_test.cpp)

add_executable(EIB_CH_MD_test src/scheme/EIB_CH_MD.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/EIB_CH_MD_test.cpp)

add_executable(DLB_CH_KEF_test src/scheme/DLB_CH_KEF.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/DLB_CH_KEF_test.cpp)

add_executable(IB_CH_Zhang_test src/scheme/IB_CH_Zhang.cpp
        src/curve/params.cpp
        src/utils/func.cpp
        unit_test/IB_CH_Zhang_test.cpp)
        
# target_link_libraries(IB_CH_Zhang_test pbc OpenSSL::SSL
#         "/lib/x86_64-linux-gnu/libgmpxx.a"
#         "/lib/x86_64-linux-gnu/libgmp.a")

add_executable(IB_CH_nonRO_test src/scheme/IB_CH_nonRO.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/IB_CH_nonRO_test.cpp)
        
# target_link_libraries(IB_CH_nonRO_test pbc OpenSSL::SSL
#         "/lib/x86_64-linux-gnu/libgmpxx.a"
#         "/lib/x86_64-linux-gnu/libgmp.a")

add_executable(IB_CH_KEF_test src/scheme/IB_CH_KEF.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/IB_CH_KEF_test.cpp)
        
# target_link_libraries(IB_CH_KEF_test pbc OpenSSL::SSL
#         "/lib/x86_64-linux-gnu/libgmpxx.a"
#         "/lib/x86_64-linux-gnu/libgmp.a")

add_executable(IB_CH_Our_test src/scheme/IB_CH_Our.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/IB_CH_Our_test.cpp)
        
# target_link_libraries(IB_CH_Our_test pbc OpenSSL::SSL
#         "/lib/x86_64-linux-gnu/libgmpxx.a"
#         "/lib/x86_64-linux-gnu/libgmp.a")
