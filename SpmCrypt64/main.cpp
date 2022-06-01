// crypt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "SpmBlockCipher64.h"
#include "UnitTests.h"
#include <time.h>


// impleemnted in key.cpp
HRESULT MakeKey(
    BYTE            *pbKey,
    size_t           cbKey
    );

char ctoh(char c)
{
    if(('0' <= c) && ('9' >= c))
    {
        return c - '0';
    }
    else if(('a' <= c) && ('z' >= c))
    {
        return 10 + c - 'a';
    }
    else if(('A' <= c) && ('Z' >= c))
    {
        return 10 + c - 'A';
    }

    return 0;
}

unsigned long atoh(__in_z const char * pszText)
{
    unsigned long dwResult = 0;
    while(*pszText >= L'0')
    {
        dwResult = (dwResult << 4) + ctoh(*pszText);
        ++pszText;
    }

    return dwResult;
}

void HexToBin(__inout_z char * pszHex, __in size_t cchBin, __out_ecount(cchBin) unsigned char* pBin)
{
    char * pszTemp;
    size_t i = cchBin - 1;

    // start at the end
    pszTemp = pszHex + strlen(pszHex) - 2;
    while((pszTemp > pszHex)&&(i < cchBin))
    {
        pBin[i] = static_cast<unsigned char>(atoh(pszTemp));
        *pszTemp = 0;
        pszTemp -= 2;
        --i;
    }

    // convert the last char, this may be a partial value (one nybble instead of two)
    if(i < cchBin)
    {
        pBin[i] = static_cast<unsigned char>(atoh(pszHex));
        while((--i) < cchBin)
        {
            pBin[i] = 0;
        }
    }
}

void HexToBin(__inout_z char * pszHex, __in size_t nAlign, __out size_t* pcchBin, __out unsigned char** ppBin)
{
    *pcchBin = strlen(pszHex) / 2;
    if ( ( ( (*pcchBin) / nAlign) * nAlign) < (*pcchBin) )
    {
        *pcchBin = ( 1 + ( (*pcchBin) / nAlign) ) * nAlign;
    }

    *ppBin = new unsigned char[*pcchBin];

    HexToBin(pszHex, *pcchBin, *ppBin);
}

void PrintBin(__in_ecount(cBin) unsigned char * pBin, __in size_t cBin)
{
    char rgBuf[3];
    while (cBin)
    {
        _itoa(*pBin,rgBuf,16);
        printf(rgBuf);
        --cBin;
        ++pBin;
    }
}

void PrintBin(__in_ecount(cBin) unsigned long * pBin, __in size_t cBin)
{
    PrintBin(reinterpret_cast<unsigned char *>(pBin), cBin * sizeof (*pBin) / sizeof (unsigned char));
}

void Log(const char * pszText, const char * pszFile)
{
    FILE* pFile = fopen(pszFile, "a");
    if(NULL != pFile)
    {
        fprintf(pFile, pszText);
        fclose(pFile);
    }
}

void ParsePassword(__inout_z const char* pszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin)
{
    size_t i = 0;
    bool fFirstPass = true;
    bool fPasswordIncomplete = true;
    const char* pszTemp = NULL;

    *ppBin = new unsigned char[cbBin];
    memset(*ppBin, 0, cbBin);

    pszTemp = pszPassword;

    while (fFirstPass || ((*pszTemp) && fPasswordIncomplete))
    {
        if ((*pszTemp) == 0)
        {
            pszTemp = pszPassword;
        }

        (*ppBin)[i] += *pszTemp;
        ++pszTemp;

        if ((*pszTemp) == 0)
        {
            fPasswordIncomplete = false;
        }

        ++i;
        if (i >= cbBin)
        {
            fFirstPass = false;
            i = 0;
        }
    }
}

void Usage()
{
    printf("Usage:\n\nFbCrypt64 E|EP|D|DP|K|L|R filein fileout key codebook\n");
}

void PRNGUsage()
{
    printf("Usage:\n\nFbCrypt64 R sample numrows numcols minrow maxrow mincol maxcol filename key\n");
}

void LinearPRNGUsage()
{
    printf("Usage:\n\nFbCrypt64 L samplesize bytespersample filename key\n");
}

void GenKeyUsage()
{
    printf("Usage:\n\nFbCrypt64 K\n\nCan be used for a key or a codebook");
}

void InvalidKey()
{
    printf("Error: that key is not valid\n");
}

void MissingNonce()
{
    Usage();
    printf("Error: Nonce is required for encryption\n");
}

void UnusedNonce()
{
    Usage();
    printf("Error: Nonce is read from input file for decryption\n");
}

void NonceWrongSize()
{
    Usage();
    printf("Error: Nonce must be same size as key\n");
}

void NonceDataWidth()
{
    Usage();
    printf("Error: Nonce should not include a data width\n");
}

/*
void InvalidKey()
{
    Usage();
    printf("Error: Invalid key format\n"
        "First 32 bit word of key is keywidth (in 32 bit words)\n"
        "Total keys size must be an even multiple of the keywidth\n"
        "Total keys size must also be >= 3 * keywidth\n");
}
*/

void FileError(__in const char * pszError, __in const char * pszFile)
{
    printf("Error: Could not %s %s\n", pszError, pszFile);
}

enum EFileCryptProcess
{
    EFCP_Encrypt,
    EFCP_Decrypt
};

void FbcProcessFile(HANDLE hFileIn, HANDLE hFileOut, ULONGLONG cbFileSize, FBC_CRYPT* pCyptor, EFileCryptProcess eFileCryptProcess)
{
    unsigned char rgBuf[0x20000] = {0};
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    DWORD cbBytesToWrite = 0;
    DWORD cbBlockAlignedBytesRead = 0;
    ULONGLONG ullTotalBytes = 0;
    clock_t nStart;
    clock_t nFinish;

    C_ASSERT ((sizeof(rgBuf) % k_cSpmBlockSizeBytes) == 0);

    nStart = clock();

    do
    {

        ReadFile(hFileIn, rgBuf, sizeof(rgBuf), &dwBytesRead, NULL);

        if(0 < dwBytesRead)
        {
            cbBlockAlignedBytesRead = (((dwBytesRead-1) / k_cSpmBlockSizeBytes)+1) * k_cSpmBlockSizeBytes;

            ASSERT (cbBlockAlignedBytesRead <= sizeof(rgBuf));

            switch (eFileCryptProcess)
            {
            case EFCP_Encrypt:
                pCyptor->Encrypt(rgBuf, cbBlockAlignedBytesRead);
                cbBytesToWrite = cbBlockAlignedBytesRead;
                break;
            case EFCP_Decrypt:
                pCyptor->Decrypt(rgBuf, cbBlockAlignedBytesRead);
                cbBytesToWrite = (DWORD)(min((ULONGLONG)dwBytesRead, cbFileSize - ullTotalBytes));
                break;
            }

            WriteFile(hFileOut, rgBuf, cbBytesToWrite, &dwBytesWritten, NULL);
            if(cbBytesToWrite != dwBytesWritten)
            {
                FileError("write", "fileout");
                exit(-13);
            }

            ullTotalBytes += dwBytesWritten;
        }
    }
    while (dwBytesRead == sizeof(rgBuf));

    nFinish = clock();

    printf("\nDe/Encrypted %I64u Kbytes in %lu ms\n", ullTotalBytes >> 10,
        static_cast<unsigned long>(nFinish - nStart));
    if(nFinish > nStart)
    {
        printf("%lu Mbits per second\n",
            (static_cast<unsigned long>((ullTotalBytes * 1000I64) >> 17)) / (nFinish - nStart)
            );
    }
}

// Apply Nonce will set keys on pCryptor
// use the realy key to encrypt the nonce to create a temporary key for this file
void ApplyNonce(unsigned char * pNonce, size_t cNonce, const unsigned char * pKey, size_t cKey, FBC_CRYPT* pCryptor)
{
    FBC_CRYPT OneWayHash;
    unsigned char rgTemp[k_cSpmBlockSizeBytes] = { 0 };

    ASSERT (k_cSpmBlockSizeBytes >= cNonce);
    ASSERT (cKey == pCryptor->s_GetKeyWidth());

#if DIAGNOSTIC_OUTPUT ==1
    printf("Raw Nonce:\n");
    PrintBin(pNonce, cNonce);
    printf("\n");
#endif //DIAGNOSTIC_OUTPUT ==1


    OneWayHash.SetKeys(pKey, cKey);

    ::memcpy(rgTemp, pNonce, cNonce);
    OneWayHash.Encrypt(rgTemp, k_cSpmBlockSizeBytes);

#if DIAGNOSTIC_OUTPUT ==1
    printf("Encrypted Nonce:\n");
    PrintBin(pNonce, cNonce);
    printf("\n");
#endif //DIAGNOSTIC_OUTPUT ==1

    ASSERT (cKey <= cNonce);
    pCryptor->SetKeys(rgTemp, cKey);
}


int InitCodebook(char* pKeyData, CSpmBlockCipher64::BLOCK_MODE eBlockMode)
{
    size_t cKey = 0;
    unsigned char * pKey = NULL;

    HexToBin(pKeyData, 1, &cKey, &pKey);

    if ( cKey < SPM_PRNG::s_GetKeyWidth() )
    {
        InvalidKey();
        delete [] pKey;
        return -1;
    }

    FBC_CRYPT::s_ConstructCodebook(eBlockMode);

    FBC_CRYPT::s_PermuteCodebook(16, pKey, cKey);
    delete [] pKey;

#ifdef _DEBUG
    FBC_CRYPT::s_CheckCodebook();
#endif

    return 0;
}




void LinearSample(const char * pFilename, unsigned char * pKey, size_t cbKey, ULONG ulCount, UCHAR ubBytes)
{
    unsigned char * pTestData = NULL;
    size_t cbTestData = ulCount * ubBytes;
    FBC_CRYPT prngTest;
    FILE* pOut = NULL;
    size_t i=0;
    clock_t nStart;
    clock_t nFinish;

    prngTest.s_PrintCipherName();

    pTestData = new unsigned char[cbTestData];

    ::memset(pTestData, 0, cbTestData);

    prngTest.SetKeys(pKey,cbKey);

    nStart = clock();

    prngTest.Encrypt(pTestData, cbTestData);

    nFinish = clock();

    printf("Sampled %lu data points in %lu ms\n",
        static_cast<ULONG>(cbTestData),
        static_cast<ULONG>(nFinish - nStart));

    if(nFinish > nStart)
    {
        ULONGLONG ullSampleSizeKBits = (cbTestData >> 5);

        printf("%lu Mbits per second\n",
            static_cast<ULONG>( ((ullSampleSizeKBits * 1000I64) >> 10) / (nFinish - nStart) )
            );
    }

    pOut = fopen(pFilename, "w");
    if(pOut)
    {
        for(i=0; cbTestData > (i * ubBytes); ++i)
        {
            switch (ubBytes)
            {
            case 1:
                fprintf(pOut, "%hu\n", static_cast<USHORT>(pTestData[i]));
                break;
            case 2:
                fprintf(pOut, "%hu\n", reinterpret_cast<USHORT*>(pTestData)[i]);
                break;
            case 4:
                fprintf(pOut, "%lu\n", pTestData[i]);
                break;
            }
        }
        fclose(pOut);
    }
}

int FbcEncryptFile(const char * pPlaintext, const char * pCiphertext, const unsigned char * pKey, size_t cbKey)
{
    FBC_CRYPT prngCrypt;
    HANDLE hFileIn = NULL;
    HANDLE hFileOut = NULL;
    BOOL fOK = FALSE;
    size_t cNonce = 0;
    unsigned char * pNonce = NULL;
    DWORD dwBytes = 0;
    ULONGLONG cbFileSize = 0;

    prngCrypt.s_PrintCipherName();

    // open input and output files
    hFileIn = ::CreateFile(pPlaintext, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(INVALID_HANDLE_VALUE == hFileIn)
    {
        FileError("open", pPlaintext);
        return -4;
    }

    fOK = GetFileSizeEx(hFileIn, reinterpret_cast<LARGE_INTEGER*>(&cbFileSize));
    if ((!fOK))
    {
        FileError("get file size", pCiphertext);
        return -13;
    }


    hFileOut = ::CreateFile(pCiphertext, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(INVALID_HANDLE_VALUE == hFileOut)
    {
        FileError("open", pCiphertext);
        return -5;
    }

    cNonce = FBC_CRYPT::s_GetKeyWidth();
    pNonce = new unsigned char [cNonce];

    if (FAILED(MakeKey(pNonce, cNonce)))
    {
        printf("Error: failed to create nonce\n");
    }

    fOK = ::WriteFile(hFileOut, pNonce, static_cast<DWORD>(cNonce * sizeof (*pNonce)), &dwBytes, NULL);
    if ((!fOK) || (dwBytes != (cNonce * sizeof (*pNonce))))
    {
        FileError("write", pCiphertext);
        delete [] pNonce;
        return -11;
    }

    fOK = ::WriteFile(hFileOut, &cbFileSize, static_cast<DWORD>(sizeof (cbFileSize)), &dwBytes, NULL);
    if ((!fOK) || (dwBytes != sizeof (cbFileSize)))
    {
        FileError("write", pCiphertext);
        delete [] pNonce;
        return -11;
    }

    ApplyNonce(pNonce, cNonce, pKey, cbKey, &prngCrypt);

    delete [] pNonce;

    FbcProcessFile(hFileIn, hFileOut, cbFileSize, &prngCrypt, EFCP_Encrypt);

    return 0;
}

int FbcDecryptFile(const char * pCiphertext, const char * pPlaintext, const unsigned char * pKey, size_t cbKey)
{
    FBC_CRYPT prngCrypt;
    HANDLE hFileIn = NULL;
    HANDLE hFileOut = NULL;
    BOOL fOK = FALSE;
    size_t cNonce = 0;
    unsigned char * pNonce = NULL;
    DWORD dwBytes = 0;
    ULONGLONG cbFileSize = 0;

    prngCrypt.s_PrintCipherName();


    // open input and output files
    hFileIn = ::CreateFile(pCiphertext, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(INVALID_HANDLE_VALUE == hFileIn)
    {
        FileError("open", pPlaintext);
        return -4;
    }

    hFileOut = ::CreateFile(pPlaintext, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(INVALID_HANDLE_VALUE == hFileOut)
    {
        FileError("open", pCiphertext);
        return -5;
    }

    // read nonce from input file
    cNonce = FBC_CRYPT::s_GetKeyWidth();
    pNonce = new unsigned char [cNonce];

    fOK = ::ReadFile(hFileIn, pNonce, static_cast<DWORD>(cNonce * sizeof (*pNonce)), &dwBytes, NULL);
    if ((!fOK) || (dwBytes != (cNonce * sizeof (*pNonce))))
    {
        FileError("read", pCiphertext);
        delete [] pNonce;
        return -12;
    }

    fOK = ::ReadFile(hFileIn, &cbFileSize, static_cast<DWORD>(sizeof (cbFileSize)), &dwBytes, NULL);
    if ((!fOK) || (dwBytes != sizeof (cbFileSize)))
    {
        FileError("read", pCiphertext);
        delete [] pNonce;
        return -12;
    }

    ApplyNonce(pNonce, cNonce, pKey, cbKey, &prngCrypt);

    delete [] pNonce;

    FbcProcessFile(hFileIn, hFileOut, cbFileSize, &prngCrypt, EFCP_Decrypt);

    return 0;
}


int PRNGTest(int argc, _TCHAR* argv[])
{
    size_t cchKey = 0;
    unsigned char * pKey = NULL;
    size_t cchRows;
    size_t cchCols;
    ULONG ulCount;
    ULONG ulMinRow;
    ULONG ulMaxRow;
    ULONG ulMinCol;
    ULONG ulMaxCol;

    if((11 != argc))
    {
        PRNGUsage();
        return -1;
    }

    ulCount = atol(argv[2]);
    cchRows = atol(argv[3]);
    cchCols = atol(argv[4]);
    ulMinRow = atol(argv[5]);
    ulMaxRow = atol(argv[6]);
    ulMinCol = atol(argv[7]);
    ulMaxCol = atol(argv[8]);

    HexToBin(argv[10], 1, &cchKey, &pKey);

    return 0;
}

CSpmBlockCipher64::BLOCK_MODE ParseBlockMode(int argc, _TCHAR* argv[])
{
    return ((2 <= argc) && (argv[1][1] == 'P')) ?
        CSpmBlockCipher64::BLOCK_MODE::Permutation : 
        CSpmBlockCipher64::BLOCK_MODE::NoPermutation;
}

int DoEncrypt(int argc, _TCHAR* argv[])
{
    size_t cKey = 0;
    unsigned char * pKey = NULL;
    int nRetVal = 0;

    if((6 != argc))
    {
        Usage();
        return -1;
    }

    nRetVal = InitCodebook (argv[5], ParseBlockMode(argc, argv));
    if (nRetVal != 0)
    {
        return nRetVal;
    }

    HexToBin(argv[4], 1, &cKey, &pKey);

    if ( ! ( FBC_CRYPT::s_ValidKey (pKey, cKey) ) )
    {
        delete[] pKey;

        cKey = FBC_CRYPT::s_GetKeyWidth();
        pKey = NULL;

        ParsePassword(argv[4], cKey, &pKey);
    }

    nRetVal = FbcEncryptFile(argv[2], argv[3], pKey, cKey);

    delete [] pKey;

    return nRetVal;
}

int DoDecrypt(int argc, _TCHAR* argv[])
{
    size_t cKey = 0;
    unsigned char * pKey = NULL;
    int nRetVal = 0;

    if((6 != argc))
    {
        Usage();
        return -1;
    }

    nRetVal = InitCodebook (argv[5], ParseBlockMode(argc, argv));
    if (nRetVal != 0)
    {
        return nRetVal;
    }

    HexToBin(argv[4], 1, &cKey, &pKey);
    cKey;

    if ( ! ( FBC_CRYPT::s_ValidKey (pKey, cKey) ) )
    {
        delete[] pKey;

        cKey = FBC_CRYPT::s_GetKeyWidth();
        pKey = NULL;

        ParsePassword(argv[4], cKey, &pKey);
    }

    nRetVal = FbcDecryptFile(argv[2], argv[3], pKey, cKey);

    delete [] pKey;

    return nRetVal;
}

int LinearPRNGTest(int argc, _TCHAR* argv[])
{
    size_t cbKey = 0;
    unsigned char * pKey = NULL;
    ULONG ulCount;
    UCHAR ucBytes;

    if((6 != argc))
    {
        LinearPRNGUsage();
        return -1;
    }

    ulCount = atol(argv[2]);
    ucBytes = static_cast<UCHAR>(atol(argv[3]));

    HexToBin(argv[5], 1, &cbKey, &pKey);

    if (!(FBC_CRYPT::s_ValidKey ( pKey, cbKey ) ) )
    {
        InvalidKey();
        delete [] pKey;
        return -1;
    }

    LinearSample(argv[4], pKey, cbKey, 
        ulCount, ucBytes);

    delete [] pKey;

    return 0;
}




int GenKey()
{
    size_t cbKey = 0;
    unsigned char* pKey = NULL;
    size_t i = 0;
    FBC_CRYPT prngCrypt;

    prngCrypt.s_PrintCipherName();


    cbKey = FBC_CRYPT::s_GetKeyWidth();

    pKey = new unsigned char[cbKey];

    if (SUCCEEDED(MakeKey(pKey, cbKey)))
    {
        printf("\n");
        for (i = 0; cbKey > i; ++i)
        {
            printf("%2.2X", pKey[i]);
        }
        printf("\n");
    }

    return 0;
}


int _tmain(int argc, _TCHAR* argv[])
{
    if((2 > argc))
    {
        Usage();
        return -1;
    }

    printf("\nFast block cipher with permutation 64 bit version 2.0.20220527\n");

    if (((*(argv[1])) == 'L') || ((*(argv[1])) == 'l'))
    {
        return LinearPRNGTest(argc, argv);
    }

    if (((*(argv[1])) == 'E') || ((*(argv[1])) == 'e'))
    {
        return DoEncrypt(argc, argv);
    }

    if (((*(argv[1])) == 'D') || ((*(argv[1])) == 'd'))
    {
        return DoDecrypt(argc, argv);
    }

    if (((*(argv[1])) == 'K') || ((*(argv[1])) == 'k'))
    {
        return GenKey();
    }

#ifdef _DEBUG
    if (((*(argv[1])) == 'T') || ((*(argv[1])) == 't'))
    {
        char pCodebook[33] = "b6a4c072764a2233db9c23b0bc79c143";

        ::InitCodebook(pCodebook, FBC_CRYPT::BLOCK_MODE::Permutation);

        UnitTests::s_PermutationEncryptTest();
        UnitTests::s_PrngTest();
        UnitTests::s_NonceTest();
        return 0;
    }
#endif // _DEBUG

    //oops this is not impemented yet:

    Usage();

    return 0;
}

