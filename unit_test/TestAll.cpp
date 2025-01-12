#include <gtest/gtest.h>

TEST(BLS_test, UNIVERSAL_TEST) {  
    std::string command = "./BLS_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}
TEST(MA_ABE_test, UNIVERSAL_TEST) {  
    std::string command = "./MA_ABE_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}
TEST(RABE_TMM_test , UNIVERSAL_TEST) {  
    std::string command = "./RABE_TMM_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}
TEST(RABE_test, UNIVERSAL_TEST) {  
    std::string command = "./RABE_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}
TEST(AES_test, UNIVERSAL_TEST){
    std::string command = "./AES_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}
TEST(CP_ABE_test, UNIVERSAL_TEST) {  
    std::string command = "./CP_ABE_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(DPCH_MXN_2022_test, UNIVERSAL_TEST) {  
    std::string command = "./DPCH_MXN_2022_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_ET_BC_CDK_2017_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_ET_BC_CDK_2017_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(RPCH_TMM_2022_test, UNIVERSAL_TEST) {  
    std::string command = "./RPCH_TMM_2022_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_FS_ECC_CCTY_2024_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_FS_ECC_CCTY_2024_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_KEF_MH_RSA_F_AM_2004_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_KEF_MH_RSA_F_AM_2004_test";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_KEF_NoMH_AM_2004_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_KEF_NoMH_AM_2004_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(RPCH_XNM_2021_test, UNIVERSAL_TEST) {  
    std::string command = "./RPCH_XNM_2021_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}
 
TEST(CH_CDK_2017_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_CDK_2017_test";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_ET_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_ET_test a 1 all";
    int result = system(command.c_str());
}

TEST(CH_KEF_CZK_2004_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_KEF_CZK_2004_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_KEF_DLP_LLA_2012_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_KEF_DLP_LLA_2012_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_KEF_MH_SDH_DL_AM_2004_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_KEF_MH_SDH_DL_AM_2004_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CHET_RSA_CDK_2017_test, UNIVERSAL_TEST) {  
    std::string command = "./CHET_RSA_CDK_2017_test";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CR_CH_DSS_2020_test, UNIVERSAL_TEST) {  
    std::string command = "./CR_CH_DSS_2020_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_KEF_DL_CZT_2011_test, UNIVERSAL_TEST) {  
    std::string command = "./CH_KEF_DL_CZT_2011_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(IB_CH_MD_LSX_2022_test, UNIVERSAL_TEST) {  
    std::string command = "./IB_CH_MD_LSX_2022_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(FCR_CH_PreQA_DKS_2020_test, UNIVERSAL_TEST) {  
    std::string command = "./FCR_CH_PreQA_DKS_2020_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(IB_CH_KEF_CZS_2014_test, UNIVERSAL_TEST) {  
    std::string command = "./IB_CH_KEF_CZS_2014_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(IB_CH_ZSS_2003_test, UNIVERSAL_TEST) {  
    std::string command = "./IB_CH_ZSS_2003_test a 1 all 0 S1";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
    command = "./IB_CH_ZSS_2003_test a 1 all 0 S2";
    result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(ID_B_CollRes_XSL_2021_test, UNIVERSAL_TEST) {  
    std::string command = "./ID_B_CollRes_XSL_2021_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(MCH_CDK_2017_test, UNIVERSAL_TEST) {  
    std::string command = "./MCH_CDK_2017_test";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(PCHBA_TLL_2020_test, UNIVERSAL_TEST) {  
    std::string command = "./PCHBA_TLL_2020_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}



int main(int argc,char *argv[]) {
  testing::InitGoogleTest(&argc,argv);
  return RUN_ALL_TESTS();
}