cmake_minimum_required(VERSION 3.0)
project(DCH)

set(CMAKE_CXX_STANDARD 17)
SET(CMAKE_BUILD_TYPE "Debug")
# SET(CMAKE_BUILD_TYPE "Release")

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

add_executable(AES_test
        src/SE/AES.cpp
        src/utils/func.cpp
        unit_test/SE_test/AES_test.cpp
)

add_executable(PCH_DSS_2019_test
    src/scheme/PCH_DSS_2019.cpp
    src/SE/AES.cpp
    src/curve/params.cpp
    src/utils/func.cpp
    src/RSA/RSA.cpp
    unit_test/PCH_DSS_2019_test.cpp
    src/ABE/CP_ABE.cpp
    src/ABE/data_structure/access_structure.cpp
    src/ABE/data_structure/binary_tree.cpp
    src/ABE/data_structure/element_t_matrix.cpp
    src/ABE/data_structure/element_t_vector.cpp
    src/ABE/data_structure/multiway_tree.cpp
    src/ABE/data_structure/num_vector.cpp
    src/ABE/policy/policy_generation.cpp
    src/ABE/policy/policy_resolution.cpp
)

add_executable(RSA_test
    src/RSA/RSA.cpp
    unit_test/RSA_test/RSA_test.cpp    
)

add_executable(ABET_test  
        src/ABE/ABET.cpp
        src/curve/params.cpp
        src/utils/func.cpp
        unit_test/ABE_test/ABET_test.cpp
        src/ABE/data_structure/access_structure.cpp
        src/ABE/data_structure/binary_tree.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/multiway_tree.cpp
        src/ABE/data_structure/num_vector.cpp
        src/ABE/policy/policy_generation.cpp
        src/ABE/policy/policy_resolution.cpp
)

add_executable(CP_ABE_test  
        src/ABE/CP_ABE.cpp
        src/curve/params.cpp
        src/utils/func.cpp
        unit_test/ABE_test/CP_ABE_test.cpp
        src/ABE/data_structure/access_structure.cpp
        src/ABE/data_structure/binary_tree.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/multiway_tree.cpp
        src/ABE/data_structure/num_vector.cpp
        src/ABE/policy/policy_generation.cpp
        src/ABE/policy/policy_resolution.cpp
)

add_executable(CH_KEF_F_CTZ_2010_test
        src/scheme/CH_KEF_F_CTZ_2010.cpp
        src/utils/func.cpp
        unit_test/CH_KEF_F_CTZ_2010_test.cpp
)

add_executable(CH_KEF_NoMH_AM_2004_test
        src/scheme/CH_KEF_NoMH_AM_2004.cpp
        src/utils/func.cpp
        unit_test/CH_KEF_NoMH_AM_2004_test.cpp
)

add_executable(CH_CDK_2017_test 
        src/scheme/CH_CDK_2017.cpp
        src/utils/func.cpp
        src/RSA/RSA.cpp
        unit_test/CH_CDK_2017_test.cpp)

add_executable(MCH_CDK_2017_test 
        src/scheme/MCH_CDK_2017.cpp
        src/utils/func.cpp
        src/RSA/RSA.cpp
        unit_test/MCH_CDK_2017_test.cpp)

add_executable(CHET_RSA_CDK_2017_test 
        src/scheme/CHET_RSA_CDK_2017.cpp
        src/utils/func.cpp
        src/RSA/RSA.cpp
        unit_test/CHET_RSA_CDK_2017_test.cpp)

add_executable(IB_CH_KEF_CZS_2014_test src/scheme/IB_CH_KEF_CZS_2014.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/IB_CH_KEF_CZS_2014_test.cpp)

add_executable(CH_KEF_DLP_LLA_2012_test src/scheme/CH_KEF_DLP_LLA_2012.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/CH_KEF_DLP_LLA_2012_test.cpp)

add_executable(CR_CH_DSS_2020_test src/scheme/CR_CH_DSS_2020.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/CR_CH_DSS_2020_test.cpp)

add_executable(FCR_CH_PreQA_DKS_2020_test src/scheme/FCR_CH_PreQA_DKS_2020.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/FCR_CH_PreQA_DKS_2020_test.cpp)

add_executable(CH_SDH_DL_AM_2004_test src/scheme/CH_SDH_DL_AM_2004.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/CH_SDH_DL_AM_2004_test.cpp)

add_executable(ID_B_CollRes_XSL_2021_test src/scheme/ID_B_CollRes_XSL_2021.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/ID_B_CollRes_XSL_2021_test.cpp)

add_executable(CH_KEF_CZK_2004_test src/scheme/CH_KEF_CZK_2004.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/CH_KEF_CZK_2004_test.cpp)

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

add_executable(IB_CH_ZSS_2003_test 
        src/scheme/IB_CH_ZSS_2003.cpp
        src/curve/params.cpp
        src/utils/func.cpp
        unit_test/IB_CH_ZSS_2003_test.cpp)
        

# google test
enable_testing() 
add_executable(TestAll unit_test/TestAll.cpp)
target_link_libraries(TestAll PRIVATE gtest pthread)
add_test(TestAll ${CMAKE_BINARY_DIR}/TestAll)
