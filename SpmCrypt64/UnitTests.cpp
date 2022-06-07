#include "stdafx.h"
#include "UnitTests.h"

#include "stdafx.h"
#include "SpmBlockCipher64.h"

int InitCodebook(char* pKeyData, CSpmBlockCipher64::BLOCK_MODE eBlockMode);
void ParsePassword(__inout_z const char* pszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin);
void HexToBin(__inout_z char* pszHex, __in size_t cchBin, __out_ecount(cchBin) unsigned char* pBin);
void PrintBin(__in_ecount(cBin) unsigned char* pBin, __in size_t cBin);
HRESULT MakeKey(    BYTE* pbKey,    size_t           cbKey);
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

// test if a single bit is changed in the input all output bits change with equal likelihood.
void UnitTests::s_SingleBitFlipTest()
{
    unsigned char rgKey[4 * sizeof(SPM_WORD)] = { 0 };
    char pDataHex[257] = "0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C";
    FBC_CRYPT encryptor1;
    FBC_CRYPT encryptor2;
    unsigned char rgCipherText1[k_cSpmBlockSizeBytes] = { 0 };
    unsigned char rgCipherText2[k_cSpmBlockSizeBytes] = { 0 };
    unsigned char rgData1[k_cSpmBlockSizeBytes] = { 0 };
    unsigned char rgData2[k_cSpmBlockSizeBytes] = { 0 };
    int matchCount = 0;
    int i = 0;

    ASSERT(FBC_CRYPT::s_rgCodebook[0] == 0xbe7d);
    ASSERT(FBC_CRYPT::s_rgCodebook[0xffff] == 0x655c);
    ASSERT(FBC_CRYPT::s_prgPermutationCodebook != NULL);
    ASSERT(FBC_CRYPT::s_prgPermutationCodebook[0] == 0x23);
    ASSERT(FBC_CRYPT::s_prgPermutationCodebook[k_cSpmBlockSizeBytes - 1] == 0x2f);

    ::HexToBin(pDataHex, ARRAYSIZE(rgData1), rgData1);
    ::memcpy(rgData2, rgData1, ARRAYSIZE(rgData1));
    rgData2[0] ^= 0x80; // flip 1 bit in rgData2

    for (i = 0; 128 > i; ++i)
    {
        MakeKey(rgKey, ARRAYSIZE(rgKey));
        printf("Key: ");
        PrintBin(rgKey, ARRAYSIZE(rgKey));
        printf("\n");
        ASSERT(FBC_CRYPT::s_ValidKey(rgKey, ARRAYSIZE(rgKey)));

        encryptor1.SetKeys(rgKey, ARRAYSIZE(rgKey));
        encryptor2.SetKeys(rgKey, ARRAYSIZE(rgKey));

        printf("Testing block 1\n");
        ::memcpy(rgCipherText1, rgData1, ARRAYSIZE(rgData1));
        encryptor1.Encrypt(rgCipherText1, ARRAYSIZE(rgCipherText1));
        encryptor1.SetKeys(rgKey, ARRAYSIZE(rgKey));

        // now flip 1 bit

        printf("Testing block 2\n");
        ::memcpy(rgCipherText2, rgData2, ARRAYSIZE(rgData2));
        encryptor2.Encrypt(rgCipherText2, ARRAYSIZE(rgCipherText2));

        printf("Block 1 encrypted: ");
        PrintBin(rgCipherText1, ARRAYSIZE(rgCipherText1));
        printf("\n");

        printf("Block 2 encrypted: ");
        PrintBin(rgCipherText2, ARRAYSIZE(rgCipherText2));
        printf("\n");

        matchCount = s_CompareBytes(rgCipherText1, rgCipherText2, ARRAYSIZE(rgCipherText2));
        printf("matchCount = %i\n", matchCount);
        ASSERT(matchCount < 4);
    }
}

#endif //_DEBUG