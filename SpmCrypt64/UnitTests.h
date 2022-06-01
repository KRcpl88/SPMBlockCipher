#pragma once
class UnitTests
{
public:
#if _DEBUG
    static void s_PermutationEncryptTest();
    static void s_PrngTest();
    static void s_NonceTest();
    static int s_CompareBytes(__in_ecount(cBin) unsigned char* pBin1, __in_ecount(cBin) unsigned char* pBin2, __in size_t cBin);
#endif
};

