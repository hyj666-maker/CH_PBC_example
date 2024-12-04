#include <gtest/gtest.h>
 
int add(int a, int b) {
  return a + b;
}
 
TEST(CH_CDK_2017_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_CDK_2017_test";
    int result = system(command.c_str());
}

TEST(CH_ET_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_ET_test a 1 all";
    int result = system(command.c_str());
}

TEST(CH_KEF_CZK_2004_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_KEF_CZK_2004_test a 1 all";
    int result = system(command.c_str());
}

TEST(CH_KEF_DLP_LLA_2012_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_KEF_DLP_LLA_2012_test a 1 all";
    int result = system(command.c_str());
}

TEST(CH_SDH_DL_AM_2004_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_SDH_DL_AM_2004_test a 1 all";
    int result = system(command.c_str());
}

TEST(CHET_RSA_CDK_2017_test, UNIVERSAL_TEST) {  
    std::string command = "./CHET_RSA_CDK_2017_test";
    int result = system(command.c_str());
}

TEST(CR_CH_DSS_2020_test, UNIVERSAL_TEST) {  
    std::string command = "./CR_CH_DSS_2020_test a 1 all";
    int result = system(command.c_str());
}

TEST(DLB_CH_KEF_test, UNIVERSAL_TEST) {  
    std::string command = "./DLB_CH_KEF_test a 1 all";
    int result = system(command.c_str());
}

TEST(EIB_CH_MD_test, UNIVERSAL_TEST) {  
    std::string command = "./EIB_CH_MD_test a 1 all";
    int result = system(command.c_str());
}

TEST(FCR_CH_PreQA_DKS_2020_test, UNIVERSAL_TEST) {  
    std::string command = "./FCR_CH_PreQA_DKS_2020_test a 1 all";
    int result = system(command.c_str());
}

TEST(IB_CH_KEF_CZS_2014_test, UNIVERSAL_TEST) {  
    std::string command = "./IB_CH_KEF_CZS_2014_test a 1 all";
    int result = system(command.c_str());
}

TEST(IB_CH_ZSS_2003_test, UNIVERSAL_TEST) {  
    std::string command = "./IB_CH_ZSS_2003_test a 1 all 0 S1";
    int result = system(command.c_str());
    command = "./IB_CH_ZSS_2003_test a 1 all 0 S2";
    result = system(command.c_str());
}

TEST(ID_B_CollRes_XSL_2021_test, UNIVERSAL_TEST) {  
    std::string command = "./ID_B_CollRes_XSL_2021_test a 1 all";
    int result = system(command.c_str());
}

TEST(MCH_CDK_2017_test, UNIVERSAL_TEST) {  
    std::string command = "./MCH_CDK_2017_test";
    int result = system(command.c_str());
}

TEST(PCHBA_TLL_2020_test, UNIVERSAL_TEST) {  
    std::string command = "./PCHBA_TLL_2020_test a 1 all";
    int result = system(command.c_str());
}



int main(int argc,char *argv[]) {
  testing::InitGoogleTest(&argc,argv);
  return RUN_ALL_TESTS();
}