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
            Console.Write("{0} bit SpmBlockCipher64 v2.0.20260403 with {1} bit blocksize, {2} bit sbox, and ",
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
            // reset any previous codebook state before re-initializing
            Array.Clear(CodeBook, 0, CodeBook.Length);
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

        public static void s_InitSbox(SPM_SBOX_WORD[] sbox, SPM_SBOX_WORD[] codebook, byte[] blockPermutation, byte[] permutationCodeBook)
        {
            // initialize Sbox values from codebook
            Debug.Assert(sbox != null);
            Debug.Assert(codebook != null);
            Debug.Assert(sbox.Length == SPM_SBOX_WIDTH);
            Debug.Assert(codebook.Length == SPM_SBOX_WIDTH);
            codebook.CopyTo(sbox, 0);

            if (s_blockMode == BLOCK_MODE.NoPermutation)
            {
                return;
            }

            Debug.Assert(blockPermutation != null);
            Debug.Assert(permutationCodeBook != null);
            Debug.Assert(blockPermutation.Length == BlockSizeBytes);
            Debug.Assert(permutationCodeBook.Length == BlockSizeBytes);
            permutationCodeBook.CopyTo(blockPermutation, 0);
        }

        private void InitSbox()
        {
            s_InitSbox(_sbox, CodeBook, _blockPermutation, PermutationCodeBook);
        }

        public static void s_PermuteSbox(SPM_SBOX_WORD[] sbox, SPM_SBOX_WORD[] reverseSbox, byte[] blockPermutation, SPM_PRNG sboxPrng)
        {
            SPM_SBOX_WORD rand;
            SPM_SBOX_WORD temp;
            size_t i = 0;

            size_t j = 0;
            for (j = 0; 16 > j; ++j)
            {
                for (i = 0; sbox.Length > i; ++i)
                {
                    // remember the current value for this Sbox entry
                    temp = sbox[i];
                    rand = sboxPrng.Rand();

                    // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
                    sbox[i] = sbox[rand];
                    sbox[rand] = temp;
                }
            }

            // now reverse the sbox
            for (i = 0; sbox.Length > i; ++i)
            {
                // if sbox[x] == y, reverseSbox[y] == x, so reverseSbox[sbox[x]] = x
                // example, if sbox[0] == 236, reverseSbox[236] = 0
                reverseSbox[sbox[i]] = (SPM_SBOX_WORD)(i);
            }

#if(DEBUG)
            // validate SBoxes
            var count = new byte[SPM_SBOX_WIDTH];
            var reverseCount = new byte[SPM_SBOX_WIDTH];

            // initialize Sbox values to 0, 1, 2, ... N
            for (i = 0; SPM_SBOX_WIDTH > i; ++i)
            {
                ++(count[sbox[i]]);
                Debug.Assert(count[sbox[i]] <= 1);

                ++(reverseCount[reverseSbox[i]]);
                Debug.Assert(reverseCount[reverseSbox[i]] <= 1);
            }
#endif // _DEBUG

            if (s_blockMode == BLOCK_MODE.NoPermutation)
            {
                return;
            }

            // init blockPermutation
            for (j = 0; 16 > j; ++j)
            {
                for (i = 0; blockPermutation.Length > i; ++i)
                {
                    // remember the current value for this entry
                    temp = blockPermutation[i];
                    rand = (SPM_SBOX_WORD)(sboxPrng.Rand() % (blockPermutation.Length));

                    // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
                    blockPermutation[i] = blockPermutation[rand];
                    blockPermutation[rand] = (byte)temp;
                }
            }

#if(DEBUG)
            // validate block permutation
            var blockPermutationCount = new byte[blockPermutation.Length];

            Debug.Assert(blockPermutationCount.Length == blockPermutation.Length);

            // initialize Sbox values to 0, 1, 2, ... N
            for (i = 0; blockPermutationCount.Length > i; ++i)
            {
                ++(blockPermutationCount[blockPermutation[i]]);
                Debug.Assert(blockPermutationCount[blockPermutation[i]] <= 1);
            }
#endif // _DEBUG
        }

        private void PermuteSbox()
        {
            s_PermuteSbox(_sbox, _reverseSbox, _blockPermutation, _sboxPrng);
        }

        public static byte[] s_ShuffleBlockPermutation(byte[] sourceBlockPermutation, SPM_PRNG sboxPrng)
        {
            SPM_SBOX_WORD rand;
            SPM_SBOX_WORD temp;
            size_t i = 0;
            var blockPermutation = new byte[BlockSizeBytes];

            sourceBlockPermutation.CopyTo(blockPermutation, 0);

            for (i = 0; blockPermutation.Length > i; ++i)
            {
                // remember the current value for this entry
                temp = blockPermutation[i];
                rand = (SPM_SBOX_WORD)(sboxPrng.Rand() % (blockPermutation.Length));

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

        public byte[] ShuffleBlockPermutation()
        {
            return s_ShuffleBlockPermutation(_blockPermutation, _sboxPrng);
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

        public SPM_WORD[] GetPrngStateKeys()
        {
            return new SPM_WORD[]
            {
                _sboxPrng.GetState(),
                _sboxPrng.GetKey(),
                _maskPrng.GetState(),
                _maskPrng.GetKey()
            };
        }

        public static void s_SmForwardPass(byte[] data, int blockOffset, SPM_SBOX_WORD[] sbox, SPM_PRNG maskPrng)
        {
            int k;
            SPM_SBOX_WORD mask;
            SPM_SBOX_WORD temp;

            for (k = 0; k < BlockInflectionIndex; ++k)
            {
#if DEBUG
                Console.Write(" {1}: raw {2:X4}", blockOffset, k, BitConverter.ToUInt16(data, blockOffset + k));
#endif
                // apply mask
                mask = maskPrng.Rand();
                temp = BitConverter.ToUInt16(data, blockOffset + k);
                temp ^= mask;
#if DEBUG
                Console.Write(" mask {0:X4} ({1:X4})", temp, mask);
#endif
                // apply substitution
                temp = sbox[temp];
                BitConverter.GetBytes(temp).CopyTo(data, blockOffset + k);
#if DEBUG
                Console.WriteLine(" sub {0:X4}", temp);
#endif
            }
        }

        public static void s_SmReversePass(byte[] data, int blockOffset, SPM_SBOX_WORD[] sbox, SPM_PRNG maskPrng)
        {
            int k;
            SPM_SBOX_WORD mask;
            SPM_SBOX_WORD temp;

            // now reverse
            for (k = (int)BlockInflectionIndex - 2; k >= 0; --k)
            {
#if DEBUG
                Console.Write(" {0}: raw {1:X4}", k, BitConverter.ToUInt16(data, blockOffset + k));
#endif
                // apply mask
                mask = maskPrng.Rand();
                temp = BitConverter.ToUInt16(data, blockOffset + k);
                temp ^= mask;
#if DEBUG
                Console.Write(" mask {0:X4} ({1:X4})", temp, mask);
#endif
                // apply substitution
                temp = sbox[temp];
                BitConverter.GetBytes(temp).CopyTo(data, blockOffset + k);
#if DEBUG
                Console.WriteLine(" sub {0:X4}", temp);
#endif
            }
        }

        public static void s_ApplyPermutation(byte[] data, int blockOffset, byte[] permutation, byte[] buffer)
        {
            int k;

            Debug.Assert(permutation.Length == BlockSizeBytes);

            for (k = 0; BlockSizeBytes > k; ++k)
            {
                buffer[permutation[k]] = data[blockOffset + k];
#if DEBUG
                Console.WriteLine(" map {0} -> {1} raw {2:X2}", k, permutation[k], data[blockOffset + k]);
#endif
            }
            buffer.CopyTo(data, blockOffset);
        }

        public static void s_ReverseSmForwardPass(byte[] data, int blockOffset, SPM_SBOX_WORD[] reverseSbox, SPM_SBOX_WORD[] masks, ref int maskIndex)
        {
            int k;
            SPM_SBOX_WORD temp;

            for (k = 0; k < BlockInflectionIndex; ++k)
            {
                Debug.Assert(maskIndex != 0);
                --maskIndex;
#if DEBUG
                Console.Write(" {0}: raw {1:X4}", k, BitConverter.ToUInt16(data, blockOffset + k));
#endif
                // reverse substitution
                temp = reverseSbox[BitConverter.ToUInt16(data, blockOffset + k)];
#if DEBUG
                Console.Write(" sub {0:X4}", temp);
#endif
                // reverse mask
                temp ^= masks[maskIndex];
                BitConverter.GetBytes(temp).CopyTo(data, blockOffset + k);
#if DEBUG
                Console.WriteLine(" mask {0:X4} ({1:X4})", temp, masks[maskIndex]);
#endif
            }
        }

        public static void s_ReverseSmReversePass(byte[] data, int blockOffset, SPM_SBOX_WORD[] reverseSbox, SPM_SBOX_WORD[] masks, ref int maskIndex)
        {
            int k;
            SPM_SBOX_WORD temp;

            // now reverse
            for (k = (int)BlockInflectionIndex - 2; k >= 0; --k)
            {
                Debug.Assert(maskIndex != 0);
                --maskIndex;
#if DEBUG
                Console.Write(" {0}: raw {1:X4}", k, BitConverter.ToUInt16(data, blockOffset + k));
#endif
                // reverse substitution
                temp = reverseSbox[BitConverter.ToUInt16(data, blockOffset + k)];
#if DEBUG
                Console.Write(" sub {0:X4}", temp);
#endif
                // reverse mask
                temp ^= masks[maskIndex];
                BitConverter.GetBytes(temp).CopyTo(data, blockOffset + k);
#if DEBUG
                Console.WriteLine(" mask {0:X4} ({1:X4})", temp, masks[maskIndex]);
#endif
            }
        }

        public static void s_EncryptRound(byte[] data, int blockOffset, SPM_SBOX_WORD[] sbox, SPM_PRNG maskPrng, byte[] blockPermutation, byte[] permutationBuffer)
        {
            s_SmForwardPass(data, blockOffset, sbox, maskPrng);

            s_SmReversePass(data, blockOffset, sbox, maskPrng);

            if (blockPermutation == null)
            {
                return;
            }

            // permute output
            s_ApplyPermutation(data, blockOffset, blockPermutation, permutationBuffer);
        }

        public static void s_EncryptBlock(byte[] data, int blockOffset, SPM_SBOX_WORD[] sbox, SPM_PRNG maskPrng, byte[] blockPermutation, byte[] permutationBuffer)
        {
            for (int j = 0; 3 > j; ++j)
            {
#if DEBUG
                Console.WriteLine("Round {0}", j);
#endif
                // blockPermutation is null when s_blockMode == BLOCK_MODE.NoPermutation;
                // s_EncryptRound treats null as a skip-permutation signal.
                s_EncryptRound(data, blockOffset, sbox, maskPrng, blockPermutation, permutationBuffer);
            }
        }

        public static void s_DecryptRound(byte[] data, int blockOffset, SPM_SBOX_WORD[] reverseSbox, SPM_SBOX_WORD[] masks, ref int maskIndex, byte[] reverseBlockPermutation, byte[] permutationBuffer)
        {
            if (reverseBlockPermutation != null)
            {
                // reverse permutation on input
                s_ApplyPermutation(data, blockOffset, reverseBlockPermutation, permutationBuffer);
#if DEBUG
                Console.Write(" Unscrambled data: ");
                foreach (byte c in permutationBuffer)
                {
                    Console.Write("{0:X2}", c);
                }
                Console.WriteLine();
#endif
            }

            s_ReverseSmForwardPass(data, blockOffset, reverseSbox, masks, ref maskIndex);

            s_ReverseSmReversePass(data, blockOffset, reverseSbox, masks, ref maskIndex);
        }

        public static void s_DecryptBlock(byte[] data, int blockOffset, SPM_SBOX_WORD[] reverseSbox, SPM_PRNG maskPrng, byte[] reverseBlockPermutation, byte[] permutationBuffer)
        {
            int maskIndex = 0;
            var mask = new SPM_SBOX_WORD[6 * BlockInflectionIndex - 3];

            // fill rgMask for all 3 rounds
            for (int j = 0; 3 > j; ++j)
            {
                for (int k = 0; k < (2 * BlockInflectionIndex - 1); ++k)
                {
                    mask[maskIndex] = maskPrng.Rand();
                    ++maskIndex;
                }
            }

            // decrypt rounds in reverse order
            for (int j = 2; 0 <= j; --j)
            {
#if DEBUG
                Console.WriteLine("Round {0}", j);
#endif
                // reverseBlockPermutation is null when s_blockMode == BLOCK_MODE.NoPermutation;
                // s_DecryptRound treats null as a skip-permutation signal.
                s_DecryptRound(data, blockOffset, reverseSbox, mask, ref maskIndex, reverseBlockPermutation, permutationBuffer);
            }
        }

        public void Encrypt(byte[] data)
        {
            int i;
            byte[] blockPermutation = null;
            var permutationBuffer = new byte[BlockSizeBytes];

            Debug.Assert((data.Length % BlockSizeBytes) == 0);

            for (i = 0; i < data.Length; i += (int)BlockSizeBytes)
            {
#if DEBUG
                Console.WriteLine("Encrypting block {0}", i / BlockSizeBytes);
#endif
                // check for BLOCK_MODE::Permutation
                if (s_blockMode == BLOCK_MODE.Permutation)
                {
                    blockPermutation = ShuffleBlockPermutation();
                }

                // blockPermutation is null when s_blockMode == BLOCK_MODE.NoPermutation;
                // s_EncryptBlock treats null as a skip-permutation signal.
                s_EncryptBlock(data, i, _sbox, _maskPrng, blockPermutation, permutationBuffer);
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

        public void Decrypt(byte[] data)
        {
            int i;
            var permutationBuffer = new byte[BlockSizeBytes];
            byte[] reverseBlockPermutation = null;

            Debug.Assert((data.Length % BlockSizeBytes) == 0);

            for (i = 0; i < data.Length; i += (int)BlockSizeBytes)
            {
#if DEBUG
                Console.WriteLine("Decrypting block {0}", i / BlockSizeBytes);
#endif
                // check for BLOCK_MODE::Permutation
                if (s_blockMode == BLOCK_MODE.Permutation)
                {
                    reverseBlockPermutation = ReverseBlockPermutation(ShuffleBlockPermutation());
                }

                // reverseBlockPermutation is null when s_blockMode == BLOCK_MODE.NoPermutation;
                // s_DecryptBlock treats null as a skip-permutation signal.
                s_DecryptBlock(data, i, _reverseSbox, _maskPrng, reverseBlockPermutation, permutationBuffer);
            }
        }
    }
}
