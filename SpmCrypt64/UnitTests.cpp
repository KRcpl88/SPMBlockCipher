#include "stdafx.h"
#include "UnitTests.h"

#include "stdafx.h"
#include "SpmBlockCipher64.h"

int InitCodebook(char* pKeyData, CSpmBlockCipher64::BLOCK_MODE eBlockMode);
void ParsePassword(__inout_z const char* pszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin);
void HexToBin(__inout_z char* pszHex, __in size_t cchBin, __out_ecount(cchBin) unsigned char* pBin);
void PrintBin(__in_ecount(cBin) unsigned char* pBin, __in size_t cBin);

#ifdef _DEBUG

int UnitTests::s_CompareBytes(__in_ecount(cBin) unsigned char* pBin1, __in_ecount(cBin) unsigned char* pBin2, __in size_t cBin)
{
    int i = 0;
    int nMatchCount = 0;

    for (i = 0; i < cBin; ++i)
    {
        if (pBin1[i] == pBin2[i])
        {
            ++nMatchCount;
        }
    }

    return nMatchCount;
}

void UnitTests::s_PermutationEncryptTest()
{
    unsigned char* pKey = new unsigned char[FBC_CRYPT::s_GetKeyWidth()];
    int nRetVal = 0;
    int nMatchCount = 0;
    char pPassword[16] = "P@s$w0rd!";

    ASSERT(FBC_CRYPT::s_rgCodebook[0] == 0xbe7d);
    ASSERT(FBC_CRYPT::s_rgCodebook[0xffff] == 0x655c);
    ASSERT(FBC_CRYPT::s_prgPermutationCodebook != NULL);
    ASSERT(FBC_CRYPT::s_prgPermutationCodebook[0] == 0x23);
    ASSERT(FBC_CRYPT::s_prgPermutationCodebook[k_cSpmBlockSizeBytes-1] == 0x2f);

    ::ParsePassword(pPassword, FBC_CRYPT::s_GetKeyWidth(), &pKey);
    ASSERT(FBC_CRYPT::s_ValidKey(pKey, FBC_CRYPT::s_GetKeyWidth()));

    unsigned char* pTestData = new unsigned char[k_cSpmBlockSizeBytes * 2];
    ::memset(pTestData, 0, k_cSpmBlockSizeBytes * 2);
    ::strncpy((char*)pTestData, "Block 1", k_cSpmBlockSizeBytes * 2);
    ::strncpy((char*)pTestData + k_cSpmBlockSizeBytes, "Block 2", k_cSpmBlockSizeBytes);
    unsigned char* pBuffer = new unsigned char[k_cSpmBlockSizeBytes * 2];
    ::memcpy(pBuffer, pTestData, k_cSpmBlockSizeBytes * 2);

    FBC_CRYPT fbcEncrypt;
    FBC_CRYPT fbcDecrypt;

    fbcEncrypt.SetKeys(pKey, FBC_CRYPT::s_GetKeyWidth());
    fbcDecrypt.SetKeys(pKey, FBC_CRYPT::s_GetKeyWidth());
    fbcEncrypt.Encrypt(pBuffer, k_cSpmBlockSizeBytes * 2);

    nMatchCount = s_CompareBytes(pTestData, pBuffer, k_cSpmBlockSizeBytes * 2);
    ASSERT(nMatchCount < 8);

    ASSERT(pBuffer[0] == 0xe2);
    ASSERT(pBuffer[k_cSpmBlockSizeBytes * 2 - 1] == 0xeb);

    fbcDecrypt.Decrypt(pBuffer, k_cSpmBlockSizeBytes * 2);
    nMatchCount = s_CompareBytes(pTestData, pBuffer, k_cSpmBlockSizeBytes * 2);

    ASSERT(nMatchCount == k_cSpmBlockSizeBytes * 2);
}

void UnitTests::s_PrngTest()
{
    SPM_PRNG prng;
    unsigned char rgKey[2 * sizeof(SPM_WORD)];
    char rgKeyHex[33] = "b6a4c072764a2233db9c23b0bc79c143";

    int i;

    ::HexToBin(rgKeyHex, ARRAYSIZE(rgKey), rgKey);

    prng.SetKeys(rgKey, ARRAYSIZE(rgKey));

    ASSERT(prng.Rand() == 0xa4b6);
    ASSERT(prng.Rand() == 0x72c0);
    ASSERT(prng.Rand() == 0x4a76);
    ASSERT(prng.Rand() == 0x3322);

    for (i = 0; 65536 > i; ++ i)
    {
        prng.Rand();
    }
    ASSERT(prng.Rand() == 0x0191);
    ASSERT(prng.Rand() == 0x0a1b);
    ASSERT(prng.Rand() == 0xf03c);
    ASSERT(prng.Rand() == 0xd552);
}

void UnitTests::s_NonceTest()
{
    unsigned char* pKey;
    char pPassword[16] = "P@s$w0rd!";
    char pNonceHex[65] = "3cd20273b6a4c072764b0bc79c14314b2233db9c230bc32aa37b6a4469c2bc79";
    FBC_CRYPT OneWayHash;
    unsigned char rgTemp[k_cSpmBlockSizeBytes] = { 0 };
    unsigned char rgNonce[4 * sizeof(SPM_WORD)] = { 0 };

    ASSERT(FBC_CRYPT::s_rgCodebook[0] == 0xbe7d);
    ASSERT(FBC_CRYPT::s_rgCodebook[0xffff] == 0x655c);
    ASSERT(FBC_CRYPT::s_prgPermutationCodebook != NULL);
    ASSERT(FBC_CRYPT::s_prgPermutationCodebook[0] == 0x23);
    ASSERT(FBC_CRYPT::s_prgPermutationCodebook[k_cSpmBlockSizeBytes - 1] == 0x2f);

    ::ParsePassword(pPassword, FBC_CRYPT::s_GetKeyWidth(), &pKey);
    ASSERT(FBC_CRYPT::s_ValidKey(pKey, FBC_CRYPT::s_GetKeyWidth()));

    ::HexToBin(pNonceHex, ARRAYSIZE(rgNonce), rgNonce);
    ASSERT(FBC_CRYPT::s_ValidKey(rgNonce, FBC_CRYPT::s_GetKeyWidth()));


    printf("Raw Nonce:\n");
    PrintBin(rgNonce, FBC_CRYPT::s_GetKeyWidth());
    printf("\n");

    OneWayHash.SetKeys(pKey, FBC_CRYPT::s_GetKeyWidth());

    ::memcpy(rgTemp, rgNonce, FBC_CRYPT::s_GetKeyWidth());
    OneWayHash.Encrypt(rgTemp, k_cSpmBlockSizeBytes);

    printf("Encrypted Nonce:\n");
    PrintBin(rgTemp, OneWayHash.s_GetKeyWidth());
    printf("\n");
    ASSERT(rgTemp[0] == 0x08);
    ASSERT(rgTemp[OneWayHash.s_GetKeyWidth()-1] == 0xF3);
    
}

#endif //_DEBUG