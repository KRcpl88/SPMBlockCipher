#include "stdafx.h"


HRESULT MakeKey(
    unsigned char   *pbRandom,
    size_t           cbRandom 
    )
{
    HRESULT         hr              = S_OK;
    BOOL            fSuccess        = FALSE;
    HCRYPTPROV      hCryptProv      = NULL;
    
    // acquire provider context
    fSuccess = CryptAcquireContext (&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_SILENT | CRYPT_VERIFYCONTEXT);
    if (fSuccess)
    {
        // generate random bytes
        ZeroMemory (pbRandom, cbRandom);
        fSuccess = CryptGenRandom (hCryptProv, (DWORD)cbRandom, pbRandom);
        if (!fSuccess)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
    }

    // release context
    if (hCryptProv != NULL)
    {
        CryptReleaseContext (hCryptProv, 0);
    }

    return hr;
}

