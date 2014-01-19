#include <crypto/CryptoBackend.h>
#include <gtest/gtest.h>

using ::testing::UnitTest;

using namespace std;
using namespace crypto;

namespace {

    class CryptoBackendTests : public ::testing::Test 
    {

    };

    TEST_F(CryptoBackendTests, GenerateRandomString) {
        SecureMem<char> random = CryptoBackend().generateRandomString(100, true);
    }
}