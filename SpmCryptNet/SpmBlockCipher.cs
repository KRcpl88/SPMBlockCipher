using System;
using System.Diagnostics;


using SPM_PRNG = Spm.SimplePrng;
using SPM_WORD = System.UInt64;
using SPM_SBOX_WORD = System.UInt16;
using size_t = System.UInt32;

namespace Spm
{
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

        private static void s_CheckCodebook()
        {
            size_t i;
            var count = new byte[SPM_SBOX_WIDTH];

            for (i = 0; CodeBook.Length > i; ++i)
            {
                ++(count[CodeBook[i]]);
                Debug.Assert(count[CodeBook[i]] <= 1);
            }

            if (PermutationCodeBook == null)
            {
                return;
            }

            count = new byte[BlockSizeBytes];

            for (i = 0; BlockSizeBytes > i; ++i)
            {
                ++(count[PermutationCodeBook[i]]);
                Debug.Assert(count[PermutationCodeBook[i]] <= 1);
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

#if(DEBUG)
            s_CheckCodebook();
#endif

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

#if(DEBUG)
            // validate SBoxes
            var count = new byte[SPM_SBOX_WIDTH];
            var reverseCount = new byte[SPM_SBOX_WIDTH];

            // initialize Sbox values to 0, 1, 2, ... N
            for (i = 0; SPM_SBOX_WIDTH > i; ++i)
            {
                ++(count[_sbox[i]]);
                Debug.Assert(count[_sbox[i]] <= 1);

                ++(reverseCount[_reverseSbox[i]]);
                Debug.Assert(reverseCount[_reverseSbox[i]] <= 1);
            }
#endif // _DEBUG

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

#if(DEBUG)
            // validate SBoxes
            var blockPermutationCount = new byte[_blockPermutation.Length];

            Debug.Assert(blockPermutationCount.Length == _blockPermutation.Length);

            // initialize Sbox values to 0, 1, 2, ... N
            for (i = 0; blockPermutationCount.Length > i; ++i)
            {
                ++(blockPermutationCount[_blockPermutation[i]]);
                Debug.Assert(blockPermutationCount[_blockPermutation[i]] <= 1);
            }
#endif // _DEBUG
        }

        public byte[] ShuffleBlockPermutation(int j = 0, SPM_SBOX_WORD[,] blockPermutationEntropy = null)
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
                rand = ((blockPermutationEntropy == null) ? 
                    (SPM_SBOX_WORD)(_sboxPrng.Rand() % (blockPermutation.Length)) :
                    blockPermutationEntropy[j,i]);

                // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
                blockPermutation[i] = blockPermutation[rand];
                blockPermutation[rand] = (byte)temp;
#if DEBUG
                Console.Write("{0} <-> {1} ({2:X2} <-> {2:X2}), ", i, rand, blockPermutation[i], blockPermutation[rand]);
#endif
            }

#if DEBUG
            Console.WriteLine();
#endif
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
            byte[] blockPermutation;
            var permutationBuffer = new byte[BlockSizeBytes];


            Debug.Assert((data.Length % BlockSizeBytes) == 0);

            for (i = 0; i < data.Length; i += (int)BlockSizeBytes)
            {
#if DEBUG
                Console.WriteLine("Encrypting block {0}", i / BlockSizeBytes);
#endif

                for (j = 0; 3 > j; ++j)
                {
#if DEBUG
                    Console.WriteLine("Round {0}", j);
#endif
                    for (k = 0; k < BlockInflectionIndex; ++k)
                    {
#if DEBUG
                        Console.Write(" {1}: raw {2:X4}", i, k, BitConverter.ToUInt16(data, i + k));
#endif

                        // apply mask
                        mask = _maskPrng.Rand();
                        temp = BitConverter.ToUInt16(data, i + k);
                        temp ^= mask;
#if DEBUG
                        Console.Write(" mask {0:X4} ({1:X4})", temp, mask);
#endif
                        // apply substitution
                        temp = _sbox[temp];
                        BitConverter.GetBytes(temp).CopyTo(data, i + k);

#if DEBUG
                        Console.WriteLine(" sub {0:X4}", temp);
#endif
                    }

                    // now reverse
                    for (k -= 2; k >= 0; --k)
                    {
#if DEBUG
                        Console.Write(" {0}: raw {1:X4}", k, BitConverter.ToUInt16(data, i + k));
#endif

                        // apply mask
                        mask = _maskPrng.Rand();
                        temp = BitConverter.ToUInt16(data, i + k);
                        temp ^= mask;
#if DEBUG
                        Console.Write(" mask {0:X4} ({1:X4})", temp, mask);
#endif

                        // apply substitution
                        temp = _sbox[temp];
                        BitConverter.GetBytes(temp).CopyTo(data, i + k);
#if DEBUG
                        Console.WriteLine(" sub {0:X4}", temp);
#endif
                    }

                    // check for BLOCK_MODE::Permutation
                    if (s_blockMode == BLOCK_MODE.NoPermutation)
                    {
                        continue;
                    }

                    // permute output
                    blockPermutation = ShuffleBlockPermutation();
                    for (k = 0; BlockSizeBytes > k; ++k)
                    {
                        permutationBuffer[blockPermutation[k]] = data[i + k];
#if DEBUG
                        Console.WriteLine(" map {0} -> {1} raw {2:X2}", k, blockPermutation[k], data[i + k]);
#endif
                    }
                    permutationBuffer.CopyTo(data, i);
                }
#if DEBUG
                Console.Write(" Encrypted data: ");
                foreach (byte c in permutationBuffer)
                {
                    Console.Write("{0:X2}", c);
                }
                Console.WriteLine();
#endif
            }
        }

        public void Decrypt(byte [] data)
        {
            int i, j, k, l;
            var mask = new SPM_SBOX_WORD[6 * BlockInflectionIndex - 3];
            var blockPermutationEntropy = new SPM_SBOX_WORD[3, BlockSizeBytes];
            SPM_SBOX_WORD temp = 0;
            var permutationBuffer = new byte[BlockSizeBytes];
            byte[] reverseBlockPermutation;

            Debug.Assert((data.Length % BlockSizeBytes) == 0);

            for (i = 0; i < data.Length; i += (int)BlockSizeBytes)
            {
#if DEBUG
                Console.WriteLine("Decrypting block {0}", i / BlockSizeBytes);
#endif
                l = 0;
                for (j = 0; 3 > j; ++j)
                {
                    // fill rgMask 
                    for (k = 0; k < (2 * BlockInflectionIndex - 1); ++k)
                    {
                        mask[l] = _maskPrng.Rand();
                        ++l;
                    }

                    if (s_blockMode == BLOCK_MODE.Permutation)
                    {
                        for (k = 0; k < BlockSizeBytes; ++k)
                        {
                            blockPermutationEntropy[j,k] = (SPM_SBOX_WORD)(_sboxPrng.Rand() % BlockSizeBytes);
                        }
                    }
                }

                for (j = 2; 0 <= j; --j)
                {
#if DEBUG
                    Console.WriteLine("Round {0}", j);
#endif
                    if (s_blockMode == BLOCK_MODE.Permutation)
                    {
                        reverseBlockPermutation = ReverseBlockPermutation(ShuffleBlockPermutation(j, blockPermutationEntropy));
                        Debug.Assert(reverseBlockPermutation.Length == BlockSizeBytes);
                        // reverse permutation on input
                        for (k = 0; BlockSizeBytes > k; ++k)
                        {
                            permutationBuffer[reverseBlockPermutation[k]] = data[i + k];
#if DEBUG
                            Console.WriteLine(" map {0} -> {1} raw {2:X2}", k, reverseBlockPermutation[k], data[i + k]);
#endif
                        }
                        permutationBuffer.CopyTo(data, i);

#if DEBUG
                        Console.Write(" Unscrambled data: ");
                        foreach (byte c in permutationBuffer)
                        {
                            Console.Write("{0:X2}", c);
                        }
                        Console.WriteLine();
#endif
                    }

                    for (k = 0; k < BlockInflectionIndex; ++k)
                    {
                        Debug.Assert(l != 0);
                        --l;
#if DEBUG
                        Console.Write(" {0}: raw {1:X4}", k, BitConverter.ToUInt16(data, i + k));
#endif

                        // reverse substitution
                        temp = _reverseSbox[BitConverter.ToUInt16(data, i + k)];
#if DEBUG
                        Console.Write(" sub {0:X4}", temp);
#endif

                        // reverse mask
                        temp ^= mask[l];
                        BitConverter.GetBytes(temp).CopyTo(data, i + k);
#if DEBUG
                        Console.WriteLine(" mask {0:X4} ({1:X4})", temp, mask[l]);
#endif
                    }

                    // now reverse
                    for (k -= 2; k >= 0; --k)
                    {
                        Debug.Assert(l != 0);
                        --l;
                        // reverse substitution
#if DEBUG
                        Console.Write(" {0}: raw {1:X4}", k, BitConverter.ToUInt16(data, i + k));
#endif
                        temp = _reverseSbox[BitConverter.ToUInt16(data, i + k)];

#if DEBUG
                        Console.Write(" sub {0:X4}", temp);
#endif

                        // reverse mask
                        temp ^= mask[l];
                        BitConverter.GetBytes(temp).CopyTo(data, i + k);

#if DEBUG
                        Console.WriteLine(" mask {0:X4} ({1:X4})", temp, mask[l]);
#endif
                    }
                }
            }
        }
    }
}
