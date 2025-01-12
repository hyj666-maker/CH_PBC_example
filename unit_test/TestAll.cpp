#include <gtest/gtest.h>

/**
 * ABE test
 */
TEST(ABE_TEST, ABET_test) {  
    std::string command = "./ABET_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}
TEST(ABE_TEST, CP_ABE_test) {  
    std::string command = "./CP_ABE_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}
TEST(ABE_TEST, MA_ABE_test) {  
    std::string command = "./MA_ABE_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}
TEST(ABE_TEST, RABE_test) {  
    std::string command = "./RABE_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}
TEST(ABE_TEST, RABE_TMM_test) {  
    std::string command = "./RABE_TMM_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

/**
 * RSA test
 */
TEST(RSA_TEST, RSA_test) {  
    std::string command = "./RSA_test";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

/**
 * SE test
 */
TEST(SE_TEST, AES_test){
    std::string command = "./AES_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

/**
 * signature test
 */
TEST(SIGNATURE_TEST, BLS_test) {  
    std::string command = "./BLS_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

/**
 * CH test
 */
TEST(CH_TEST, CH_CDK_2017_test) {  
    std::string command = "./CH_CDK_2017_test";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, CH_ET_BC_CDK_2017_test) {  
    std::string command = "./CH_ET_BC_CDK_2017_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, CH_ET_test) {  
    std::string command = "./CH_ET_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, CH_FS_ECC_CCTY_2024_test) {  
    std::string command = "./CH_FS_ECC_CCTY_2024_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, CH_KEF_CZK_2004_test) {  
    std::string command = "./CH_KEF_CZK_2004_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, CH_KEF_DL_CZT_2011_test) {  
    std::string command = "./CH_KEF_DL_CZT_2011_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, CH_KEF_DLP_LLA_2012_test) {  
    std::string command = "./CH_KEF_DLP_LLA_2012_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

// CH_KEF_F_CTZ_2010_test

TEST(CH_TEST, CH_KEF_MH_RSA_F_AM_2004_test) {  
    std::string command = "./CH_KEF_MH_RSA_F_AM_2004_test";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, CH_KEF_MH_SDH_DL_AM_2004_test) {  
    std::string command = "./CH_KEF_MH_SDH_DL_AM_2004_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, CH_KEF_NoMH_AM_2004_test) {  
    std::string command = "./CH_KEF_NoMH_AM_2004_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, CHET_RSA_CDK_2017_test) {  
    std::string command = "./CHET_RSA_CDK_2017_test";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, CR_CH_DSS_2020_test) {  
    std::string command = "./CR_CH_DSS_2020_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, DPCH_MXN_2022_test) {  
    std::string command = "./DPCH_MXN_2022_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, FCR_CH_PreQA_DKS_2020_test) {  
    std::string command = "./FCR_CH_PreQA_DKS_2020_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, IB_CH_KEF_CZS_2014_test) {  
    std::string command = "./IB_CH_KEF_CZS_2014_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, IB_CH_MD_LSX_2022_test) {  
    std::string command = "./IB_CH_MD_LSX_2022_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, IB_CH_ZSS_2003_test_1) {  
    std::string command = "./IB_CH_ZSS_2003_test a 1 all 0 S1";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, IB_CH_ZSS_2003_test_2) {  
    std::string command = "./IB_CH_ZSS_2003_test a 1 all 0 S2";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, ID_B_CollRes_XSL_2021_test) {  
    std::string command = "./ID_B_CollRes_XSL_2021_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, MAPCH_ZLW_2021) {  
    std::string command = "./MAPCH_ZLW_2021_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, MCH_CDK_2017_test) {  
    std::string command = "./MCH_CDK_2017_test";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, PCH_DSS_2019_test){
    std::string command = "./PCH_DSS_2019_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, PCHBA_TLL_2020_test) {  
    std::string command = "./PCHBA_TLL_2020_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, RPCH_TMM_2022_test) {  
    std::string command = "./RPCH_TMM_2022_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}

TEST(CH_TEST, RPCH_XNM_2021_test) {  
    std::string command = "./RPCH_XNM_2021_test a 1 all";
    int result = system(command.c_str());
    ASSERT_EQ(result, 0);
}



int main(int argc,char *argv[]) {
  testing::InitGoogleTest(&argc,argv);
  return RUN_ALL_TESTS();
}