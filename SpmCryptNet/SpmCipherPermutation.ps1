$Source = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Timers;

using SPM_PRNG = Spm.SimplePrng;
using SPM_WORD = System.UInt64;
using SPM_SBOX_WORD = System.UInt16;
using size_t = System.UInt32;

namespace Spm
{
    public class Util
    {
        public enum EFileCryptProcess
        {
            Encrypt,
            Decrypt
        };


        public static byte [] ParsePassword(string password, uint cb)
        {
            uint i = 0;
            uint j = 0;
            bool firstPass = true;
            bool passwordIncomplete = true;
            byte[] temp = null;
            byte[] bin = new byte[cb];

            while (firstPass || passwordIncomplete)
            {
                if (temp == null)
                {
                    temp = Encoding.UTF8.GetBytes(password);
                    j = 0;
                }

                bin[i] += temp[j];
                ++j;

                if (j >= password.Length)
                {
                    passwordIncomplete = false;
                    j = 0;
                }

                ++i;
                if (i >= cb)
                {
                    firstPass = false;
                    i = 0;
                }
            }
            return bin;
        }

        public static byte[] HexToBin(string hex)
        {
            if(hex.Length == 0)
            {
                return null;
            }

            byte[] bin = new byte[((hex.Length-1)/2) +1];
            int i;
            int chunkLength;

            for (i = 0; i < bin.Length; ++i)
            {
                // for the last chunk, it may be 1 or 2 chars in length
                chunkLength = ((i < (bin.Length - 1)) ? 2 : (((hex.Length + 1) % 2) + 1));

                // start from the end and work backwards
                bin[bin.Length - i -1] = (byte)(Convert.ToInt32(hex.Substring((hex.Length - (i * 2 + chunkLength)), chunkLength), 16));
            }
            return bin;
        }

        public static void PrintBin(byte[] bin)
        {
            foreach(byte c in bin)
            {
                Console.Write("{0:X2}", c);
            }
        }

        public static void ApplyNonce(byte[] nonce, byte[] key, SpmBlockCipher cryptor)
        {
            var oneWayHash =  new SpmBlockCipher();
            var encryptedNonce = new byte[SpmBlockCipher.GetKeyWidth()];
            var block = new byte[SpmBlockCipher.BlockSizeBytes];

            nonce.CopyTo(block, 0);

            oneWayHash.SetKeys(key);

            oneWayHash.Encrypt(block);


            for (int i = 0; encryptedNonce.Length > i; ++i)
            {
                encryptedNonce[i] = block[i];
            }

            cryptor.SetKeys(encryptedNonce);
        }

        public static byte[] GenNonceFromInput(byte[] hashKey = null)
        {
            var oneWayHash = new SpmBlockCipher();
            var nonce = new byte[SpmBlockCipher.BlockSizeBytes];
            var buf = new byte[SpmBlockCipher.BlockSizeBytes];

            var timer = new Stopwatch();
            int i = sizeof(long);
            timer.Start();
            BitConverter.GetBytes(Environment.TickCount).CopyTo(nonce, i);
            i += sizeof(int);
            BitConverter.GetBytes(Process.GetCurrentProcess().Id).CopyTo(nonce, i);
            i += sizeof(int);
            BitConverter.GetBytes(Thread.CurrentThread.ManagedThreadId).CopyTo(nonce, i);
            i += sizeof(int);
            BitConverter.GetBytes(DateTime.Now.Ticks).CopyTo(nonce, i);
            Console.WriteLine("Press enter to collect entropy...");
            Console.Read();
            timer.Stop();

            BitConverter.GetBytes(timer.ElapsedTicks).CopyTo(nonce, 0);
            PrintBin(nonce);
            Console.WriteLine("");

            nonce.CopyTo(buf, 0);

            // apply one way hash to the noce so we dont leak info in the nonce
            if (hashKey == null)
            {
                hashKey = HexToBin("3BCC8CBF2103DDC295E70BCC305C6BB232479DD2792204A2CA83CE3BEFF9EA43");
            }
            oneWayHash.SetKeys(hashKey);
            oneWayHash.Encrypt(buf);
            Array.Copy(buf, nonce, nonce.Length / 2);
            oneWayHash.Encrypt(buf);
            Array.Copy(buf, 0, nonce, nonce.Length / 2, nonce.Length / 2);

            PrintBin(nonce);
            Console.WriteLine("");

            return nonce;
        }


        public static void SpmEncryptFile(string plaintext, string ciphertext, byte[] key)
        {
            var cryptor = new SpmBlockCipher();
            byte[] nonce;
            UInt64 fileSize;

            SpmBlockCipher.PrintCipherName();

            using (FileStream hFileIn = File.OpenRead(plaintext))
            {
                nonce = GenNonceFromInput();

                fileSize = (UInt64)hFileIn.Length;
                using (FileStream hFileOut = File.OpenWrite(ciphertext))
                {
                    hFileOut.Write(nonce, 0, nonce.Length);
                    hFileOut.Write(BitConverter.GetBytes(fileSize), 0, sizeof(UInt64));

                    ApplyNonce(nonce, key, cryptor);

                    SpmProcessFile(hFileIn, hFileOut, fileSize, cryptor, EFileCryptProcess.Encrypt);
                }
            }
        }

        public static void SpmDecryptFile(string ciphertext, string plaintext, byte[] key)
        {
            var cryptor = new SpmBlockCipher();
            var nonce = new byte[SpmBlockCipher.GetKeyWidth()];
            var fileSize = new byte[sizeof(UInt64)];
            int bytesRead = 0;

            SpmBlockCipher.PrintCipherName();

            using (FileStream hFileIn = File.OpenRead(ciphertext))
            {
                bytesRead = hFileIn.Read(nonce, 0, nonce.Length);
                if (bytesRead != nonce.Length)
                {
                    throw (new Exception("Corrupt or invalid encrypted file"));
                }
                bytesRead = hFileIn.Read(fileSize, 0, sizeof(UInt64));
                if (bytesRead != fileSize.Length)
                {
                    throw (new Exception("Corrupt or invalid encrypted file"));
                }

                using (FileStream hFileOut = File.OpenWrite(plaintext))
                {
                    ApplyNonce(nonce, key, cryptor);

                    SpmProcessFile(hFileIn, hFileOut, BitConverter.ToUInt64(fileSize, 0), cryptor, EFileCryptProcess.Decrypt);
                }
            }
        }


        static void SpmProcessFile(FileStream fileIn, FileStream fileOut, UInt64 fileSize, SpmBlockCipher cryptor, EFileCryptProcess fileCryptProcess)
        {
            var buf = new byte[SpmBlockCipher.BlockSizeBytes];
            int bytesRead;
            UInt64 totalBytes = 0;
            var timer = new Stopwatch();

            timer.Start();

            do
            {
                bytesRead = fileIn.Read(buf, 0, buf.Length);

                if (0 < bytesRead) 
                {

                    switch (fileCryptProcess)
                    {
                        case EFileCryptProcess.Encrypt:
                            cryptor.Encrypt(buf);
                            break;
                        case EFileCryptProcess.Decrypt:
                            if (bytesRead != SpmBlockCipher.BlockSizeBytes)
                            {
                                throw (new Exception("Corrupt or invalid encrypted file"));
                            }
                            cryptor.Decrypt(buf);
                            break;
                    }

                    totalBytes += (UInt64)bytesRead;

                    if (totalBytes < fileSize)
                    {
                        fileOut.Write(buf, 0, buf.Length);
                    }
                    else 
                    {
                        fileOut.Write( buf, 0, (int)(SpmBlockCipher.BlockSizeBytes - (totalBytes - fileSize)) );
                    }
                }
            }
            while (bytesRead == buf.Length);

            timer.Stop();

            Console.WriteLine("De/Encrypted {0} Kbytes in {1} ms", totalBytes >> 10,
                timer.ElapsedMilliseconds);

            if (timer.ElapsedMilliseconds > 0)
            {
                Console.WriteLine("  {0} Mbits per second",
                    ((totalBytes * 1000) >> 17) / (UInt64)(timer.ElapsedMilliseconds)
                    );
            }
        }
    }

    public class SimplePrng
    {
        private SPM_WORD _state;
        private SPM_WORD _key;
        private int _idx;
        private byte[] _data;



        public SimplePrng()
        {
            _state = 0;
            _key = 0;
        }

        public static void PrintCipherName()
        {
            Console.WriteLine("{0} bit simple PRNG ", sizeof(SPM_WORD) * 8);
        }

        public void SetKeys(byte[] keyData, int offest = 0)
        {
            _state = BitConverter.ToUInt64(keyData, offest);
            _key = BitConverter.ToUInt64(keyData, offest + sizeof(SPM_WORD));
            _key |= 1;  // make sure it is odd
            _idx = 0;
            _data = BitConverter.GetBytes(_state);
        }

        public SPM_SBOX_WORD Rand()
        {
            if (_idx >= (sizeof(SPM_WORD) / sizeof(SPM_SBOX_WORD)))
            {
                _idx = 0;
                _state += _key;
                _data = BitConverter.GetBytes(_state);
            }

            return (SPM_SBOX_WORD)(BitConverter.ToInt16(_data, (_idx++) << 1));
        }

        public static uint GetKeyWidth()
        {
            uint keyWidth;
            keyWidth = 2 * sizeof(SPM_WORD);
            return keyWidth;
        }
    }

    public class SpmBlockCipher
    {
        public const uint BlockSizeWords = 16;
        public const uint BlockSizeBytes = BlockSizeWords * sizeof(SPM_WORD);
        public const uint BlockInflectionIndex = BlockSizeBytes - sizeof(SPM_SBOX_WORD) + 1; // reverse point for encrypting block
        public const uint BlockSizeBits = BlockSizeBytes * 8;

        public const uint SpmWordWidthBits = 8 * sizeof(SPM_WORD);
        public const uint SpmSBoxWidthBits = 8 * sizeof(SPM_SBOX_WORD);

        // defines log base 2 of the width of a FBC_WORD in bytes, for 64 bit words log2(8) = 3
        public const uint SPM_LOG2_WORD_WIDTH = 3;


        // must be 2^k_cSpmSBoxWidthBits;
        public const uint SPM_SBOX_WIDTH = 0x10000;


        public static SPM_SBOX_WORD[] CodeBook = new SPM_SBOX_WORD[SPM_SBOX_WIDTH];
        public static byte[] PermutationCodeBook = null;

        public const uint FBC_PRNG_NUM_KEYS = 2;
        private SPM_PRNG _sboxPrng = new SPM_PRNG();
        private SPM_PRNG _maskPrng = new SPM_PRNG();
        private SPM_SBOX_WORD[] _sbox = new SPM_SBOX_WORD[SPM_SBOX_WIDTH];
        private SPM_SBOX_WORD[] _reverseSbox = new SPM_SBOX_WORD[SPM_SBOX_WIDTH];
        private byte[] _blockPermutation = new byte[BlockSizeBytes];

        public enum BLOCK_MODE { Permutation, NoPermutation };
        private static BLOCK_MODE s_blockMode = BLOCK_MODE.NoPermutation;

        public static void PrintCipherName()
        {
            Console.Write("{0} bit SpmBlockCipher64 with {1} bit blocksize, {2} bit sbox, and ",
                GetKeyWidth() * 8,
                BlockSizeBits,
                SpmSBoxWidthBits);
            SPM_PRNG.PrintCipherName();
        }

        public static size_t GetKeyWidth()
        {
            size_t keyWidth;
            keyWidth = SPM_PRNG.GetKeyWidth() * 2;
            return keyWidth;
        }

        private static void s_ConstructCodebook(BLOCK_MODE blockMode)
        {
            int i;
            // initialize Sbox values to 0, 1, 2, ... N
            for (i = 0; CodeBook.Length > i; ++i)
            {
                Debug.Assert(CodeBook[i] == 0);

                CodeBook[i] = (SPM_SBOX_WORD)(i);
            }

            s_blockMode = blockMode;
            PermutationCodeBook = null;
            if (blockMode == BLOCK_MODE.NoPermutation)
            {
                return;
            }

            PermutationCodeBook = new byte[BlockSizeBytes];

            // initialize permutation values to 0, 1, 2, ... N
            for (i = 0; BlockSizeBytes > i; ++i)
            {
                Debug.Assert(PermutationCodeBook[i] == 0);

                PermutationCodeBook[i] = (byte)(i);
            }
        }

        private static void s_PermuteCodebook(int n, byte[] keyData)
        {
            SPM_SBOX_WORD rand;
            SPM_SBOX_WORD temp;
            var permutorPrng = new SPM_PRNG();
            size_t j;
            int i;

            Debug.Assert(keyData.Length >= (int)SPM_PRNG.GetKeyWidth());
            permutorPrng.SetKeys(keyData);

            for (i=0; n>i; ++i)
            {
                for(j=0; CodeBook.Length > j; ++j)
                {
                    // remember the current value for this Sbox entry
                    temp = CodeBook[j];
                    rand = permutorPrng.Rand();

                    // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
                    CodeBook[j] = CodeBook[rand];
                    CodeBook[rand] = temp;
                }
            }

            // check for BLOCK_MODE.NoPermutation
            if (PermutationCodeBook == null)
            {
                return;
            }

            for (i = 0; n > i; ++i)
            {
                for (j = 0; BlockSizeBytes > j; ++j)
                {
                    // remember the current value for this Sbox entry
                    temp = PermutationCodeBook[j];
                    rand = (SPM_SBOX_WORD)(permutorPrng.Rand() % BlockSizeBytes);

                    // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
                    PermutationCodeBook[j] = PermutationCodeBook[rand];
                    PermutationCodeBook[rand] = (byte) (temp);
                }
            }
        }

        public static int InitCodebook(string keyData, BLOCK_MODE blockMode)
        {
            byte[] key = Util.HexToBin(keyData);

            if (keyData.Length < SPM_PRNG.GetKeyWidth())
            {
                return -1;
            }

            s_ConstructCodebook(blockMode);

            s_PermuteCodebook(16, key);

            return 0;
        }

        private void InitSbox()
        {
            // initialize Sbox values from codebook
            Debug.Assert(_sbox != null);
            Debug.Assert(CodeBook != null);
            Debug.Assert(_sbox.Length == SPM_SBOX_WIDTH);
            Debug.Assert(CodeBook.Length == SPM_SBOX_WIDTH);
            CodeBook.CopyTo(_sbox, 0);

            if (s_blockMode == BLOCK_MODE.NoPermutation)
            {
                return;
            }

            Debug.Assert(_blockPermutation != null);
            Debug.Assert(PermutationCodeBook != null);
            Debug.Assert(_blockPermutation.Length == BlockSizeBytes);
            Debug.Assert(PermutationCodeBook.Length == BlockSizeBytes);
            PermutationCodeBook.CopyTo(_blockPermutation, 0);
        }

        private void PermuteSbox()
        {
            SPM_SBOX_WORD rand;
            SPM_SBOX_WORD temp;
            size_t i = 0;

            size_t j = 0;
            for (j = 0; 16 > j; ++j)
            {
                for (i = 0; _sbox.Length > i; ++i)
                {
                    // remember the current value for this Sbox entry
                    temp = _sbox[i];
                    rand = _sboxPrng.Rand();

                    // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
                    _sbox[i] = _sbox[rand];
                    _sbox[rand] = temp;
                }
            }

            // now reverse the sbox
            for (i = 0; _sbox.Length > i; ++i)
            {
                // if m_rgSbox[x] == y, m_rgReverseSbox[y] == x, so m_rgReverseSbox[m_rgSbox[x]] = x
                // example, if m_rgSbox[0] == 236, m_rgReverseSbox[236] = 0
                _reverseSbox[_sbox[i]] = (SPM_SBOX_WORD)(i);
            }

            if (s_blockMode == BLOCK_MODE.NoPermutation)
            {
                return;
            }

            // init m_rgBlockPermutation
            for (j = 0; 16 > j; ++j)
            {
                for (i = 0; _blockPermutation.Length > i; ++i)
                {
                    // remember the current value for this entry
                    temp = _blockPermutation[i];
                    rand = (SPM_SBOX_WORD)(_sboxPrng.Rand() % (_blockPermutation.Length));

                    // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
                    _blockPermutation[i] = _blockPermutation[rand];
                    _blockPermutation[rand] = (byte)temp;
                }
            }
        }

        public byte[] ShuffleBlockPermutation()
        {
            SPM_SBOX_WORD rand;
            SPM_SBOX_WORD temp;
            size_t i = 0;
            var blockPermutation = new byte[BlockSizeBytes];

            _blockPermutation.CopyTo(blockPermutation, 0);

            for (i = 0; blockPermutation.Length > i; ++i)
            {
                // remember the current value for this entry
                temp = blockPermutation[i];
                rand = (SPM_SBOX_WORD)(_sboxPrng.Rand() % (blockPermutation.Length));

                // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
                blockPermutation[i] = blockPermutation[rand];
                blockPermutation[rand] = (byte)temp;
            }

            return blockPermutation;
        }

        public byte[] ReverseBlockPermutation(byte[] blockPermutation)
        {
            size_t i = 0;
            var reverseBlockPermutation = new byte[BlockSizeBytes];

            for (i = 0; blockPermutation.Length > i; ++i)
            {
                // if m_rgBlockPermutation[x] == y, rgReverseBlockPermutation[y] == x, so rgReverseBlockPermutation[rgBlockPermutation[x]] = x
                // example, if rgBlockPermutation[0] == 236, rgReverseBlockPermutation[236] = 0
                Debug.Assert(blockPermutation[i] < reverseBlockPermutation.Length);
                reverseBlockPermutation[blockPermutation[i]] = (byte)i;
            }

            return reverseBlockPermutation;
        }

        public static bool s_ValidKey(byte[] keyData)
        {
            size_t keyWidth;
            keyWidth = GetKeyWidth();
            return (keyData != null) && (keyData.Length == keyWidth);
        }

        public void SetKeys(byte[] keyData, int cbOffest = 0)
        {
            int prngKeyWidth = (int)SPM_PRNG.GetKeyWidth();
            Debug.Assert(keyData.Length >= cbOffest + prngKeyWidth + prngKeyWidth);

            _sboxPrng.SetKeys(keyData, cbOffest);
            _maskPrng.SetKeys(keyData, cbOffest + prngKeyWidth);

            InitSbox();

            PermuteSbox();
        }

        public void Encrypt(byte[] data)
        {
            int i, j, k;
            SPM_SBOX_WORD mask = 0;
            SPM_SBOX_WORD temp = 0;
            byte[] blockPermutation = null;
            var permutationBuffer = new byte[BlockSizeBytes];


            Debug.Assert((data.Length % BlockSizeBytes) == 0);

            for (i = 0; i < data.Length; i += (int)BlockSizeBytes)
            {
                // check for BLOCK_MODE::Permutation
                if (s_blockMode == BLOCK_MODE.Permutation)
                {
                    blockPermutation = ShuffleBlockPermutation();
                }

                for (j = 0; 3 > j; ++j)
                {
                    for (k = 0; k < BlockInflectionIndex; ++k)
                    {
                        // apply mask
                        mask = _maskPrng.Rand();
                        temp = BitConverter.ToUInt16(data, i + k);
                        temp ^= mask;

                        // apply substitution
                        temp = _sbox[temp];
                        BitConverter.GetBytes(temp).CopyTo(data, i + k);
                    }

                    // now reverse
                    for (k -= 2; k >= 0; --k)
                    {

                        // apply mask
                        mask = _maskPrng.Rand();
                        temp = BitConverter.ToUInt16(data, i + k);
                        temp ^= mask;

                        // apply substitution
                        temp = _sbox[temp];
                        BitConverter.GetBytes(temp).CopyTo(data, i + k);
                    }

                    // check for BLOCK_MODE::Permutation
                    if (s_blockMode == BLOCK_MODE.NoPermutation)
                    {
                        continue;
                    }

                    // permute output
                    for (k = 0; BlockSizeBytes > k; ++k)
                    {
                        permutationBuffer[blockPermutation[k]] = data[i + k];
                    }
                    permutationBuffer.CopyTo(data, i);
                }
            }
        }

        public void Decrypt(byte [] data)
        {
            int i, j, k, l;
            var mask = new SPM_SBOX_WORD[6 * BlockInflectionIndex - 3];
            SPM_SBOX_WORD temp = 0;
            var permutationBuffer = new byte[BlockSizeBytes];
            byte[] reverseBlockPermutation = null;

            Debug.Assert((data.Length % BlockSizeBytes) == 0);

            for (i = 0; i < data.Length; i += (int)BlockSizeBytes)
            {
                // check for BLOCK_MODE::Permutation
                if (s_blockMode == BLOCK_MODE.Permutation)
                {
                    reverseBlockPermutation = ReverseBlockPermutation(ShuffleBlockPermutation());
                }

                l = 0;
                for (j = 0; 3 > j; ++j)
                {
                    // fill rgMask 
                    for (k = 0; k < (2 * BlockInflectionIndex - 1); ++k)
                    {
                        mask[l] = _maskPrng.Rand();
                        ++l;
                    }
                }

                for (j = 2; 0 <= j; --j)
                {
                    if (s_blockMode == BLOCK_MODE.Permutation)
                    {
                        Debug.Assert(reverseBlockPermutation.Length == BlockSizeBytes);
                        // reverse permutation on input
                        for (k = 0; BlockSizeBytes > k; ++k)
                        {
                            permutationBuffer[reverseBlockPermutation[k]] = data[i + k];
                        }
                        permutationBuffer.CopyTo(data, i);
                    }

                    for (k = 0; k < BlockInflectionIndex; ++k)
                    {
                        Debug.Assert(l != 0);
                        --l;

                        // reverse substitution
                        temp = _reverseSbox[BitConverter.ToUInt16(data, i + k)];

                        // reverse mask
                        temp ^= mask[l];
                        BitConverter.GetBytes(temp).CopyTo(data, i + k);
                    }

                    // now reverse
                    for (k -= 2; k >= 0; --k)
                    {
                        Debug.Assert(l != 0);
                        --l;
                        // reverse substitution
                        temp = _reverseSbox[BitConverter.ToUInt16(data, i + k)];

                        // reverse mask
                        temp ^= mask[l];
                        BitConverter.GetBytes(temp).CopyTo(data, i + k);
                    }
                }
            }
        }
    }
}
"@

Add-Type -TypeDefinition $Source -Language CSharp 

[Spm.SpmBlockCipher]::InitCodebook("b6a4c072764a2233db9c23b0bc79c143", [Spm.SpmBlockCipher+BLOCK_MODE]::Permutation)
$key = [Spm.Util]::ParsePassword('P@s$sw0rd!!', [Spm.SpmBlockCipher]::GetKeyWidth())

# [Spm.Util]::SpmEncryptFile(string plaintext, string ciphertext, $key)