using Microsoft.VisualStudio.TestTools.UnitTesting;
using Spm;
using System.Linq;

namespace Spm.Tests
{
    /// <summary>
    /// Unit tests for the static methods added to SpmBlockCipher:
    /// s_SmForwardPass, s_SmReversePass, s_ApplyPermutation,
    /// s_ReverseSmForwardPass, s_ReverseSmReversePass, s_EncryptRound, and s_DecryptRound.
    /// </summary>
    [TestClass()]
    public class SpmBlockCipherStaticMethodTests
    {
        /// <summary>
        /// Builds an identity s-box: sbox[i] == i for all i.
        /// With an identity s-box the substitution step is a no-op so only the
        /// mask XOR affects the data, making round-trip tests straightforward.
        /// </summary>
        private static ushort[] BuildIdentitySbox()
        {
            var sbox = new ushort[SpmBlockCipher.SPM_SBOX_WIDTH];
            for (int i = 0; i < sbox.Length; i++)
                sbox[i] = (ushort)i;
            return sbox;
        }

        /// <summary>
        /// Returns a SimplePrng seeded with a fixed, known, non-zero key.
        /// Calling this twice produces two independently-seeded but identical PRNGs.
        /// </summary>
        private static SimplePrng BuildPrng()
        {
            var prng = new SimplePrng();
            var key = new byte[SimplePrng.GetKeyWidth()]; // 16 bytes
            for (int i = 0; i < key.Length; i++)
                key[i] = (byte)(i + 1);
            prng.SetKeys(key);
            return prng;
        }

        /// <summary>
        /// Returns a block of non-trivial test data: byte[i] = i + 1.
        /// </summary>
        private static byte[] MakeTestBlock()
        {
            var data = new byte[SpmBlockCipher.BlockSizeBytes];
            for (int i = 0; i < data.Length; i++)
                data[i] = (byte)(i + 1);
            return data;
        }

        // ──────────────────────────────────────────────────────────────────────────
        // s_SmForwardPass
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void EncryptForwardPass_TransformsData()
        {
            var original = MakeTestBlock();
            var data = (byte[])original.Clone();

            SpmBlockCipher.s_SmForwardPass(data, 0, BuildIdentitySbox(), BuildPrng());

            Assert.IsFalse(data.SequenceEqual(original),
                "s_SmForwardPass should change the data.");
        }

        [TestMethod()]
        public void EncryptForwardPass_AppliedTwiceWithSameKey_RestoresOriginalData()
        {
            // With an identity s-box, applying s_SmForwardPass twice with the
            // same PRNG seed restores the original data (involution property).
            var sbox = BuildIdentitySbox();
            var original = MakeTestBlock();
            var data = (byte[])original.Clone();

            SpmBlockCipher.s_SmForwardPass(data, 0, sbox, BuildPrng());
            SpmBlockCipher.s_SmForwardPass(data, 0, sbox, BuildPrng()); // identical seed → identical masks

            Assert.IsTrue(data.SequenceEqual(original),
                "Applying s_SmForwardPass twice with the same key should restore the original data.");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // s_SmReversePass
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void EncryptReversePass_TransformsData()
        {
            var original = MakeTestBlock();
            var data = (byte[])original.Clone();

            SpmBlockCipher.s_SmReversePass(data, 0, BuildIdentitySbox(), BuildPrng());

            Assert.IsFalse(data.SequenceEqual(original),
                "s_SmReversePass should change the data.");
        }

        [TestMethod()]
        public void EncryptReversePass_AppliedTwiceWithSameKey_RestoresOriginalData()
        {
            // Same involution property as s_SmForwardPass, but the window iterates
            // in reverse order (k = BlockInflectionIndex-2 down to 0).

            var sbox= BuildIdentitySbox();
            var original = MakeTestBlock();
            var data = (byte[])original.Clone();

            SpmBlockCipher.s_SmReversePass(data, 0, sbox, BuildPrng());
            SpmBlockCipher.s_SmReversePass(data, 0, sbox, BuildPrng()); // identical seed → identical masks

            Assert.IsTrue(data.SequenceEqual(original),
                "Applying s_SmReversePass twice with the same key should restore the original data.");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // s_ApplyPermutation
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void ApplyPermutation_IdentityPermutation_LeavesDataUnchanged()
        {
            var permutation = Enumerable.Range(0, (int)SpmBlockCipher.BlockSizeBytes)
                .Select(i => (byte)i).ToArray();
            var original = MakeTestBlock();
            var data = (byte[])original.Clone();
            var buffer = new byte[SpmBlockCipher.BlockSizeBytes];

            SpmBlockCipher.s_ApplyPermutation(data, 0, permutation, buffer);

            Assert.IsTrue(data.SequenceEqual(original),
                "Identity permutation should leave the data unchanged.");
        }

        [TestMethod()]
        public void ApplyPermutation_KnownSwapPermutation_CorrectlyRearrangesBytes()
        {
            // Permutation maps source position 0 to output slot 1 and
            // source position 1 to output slot 0, swapping the first two bytes.
            var permutation = Enumerable.Range(0, (int)SpmBlockCipher.BlockSizeBytes)
                .Select(i => (byte)i).ToArray();
            permutation[0] = 1;
            permutation[1] = 0;

            var original = MakeTestBlock(); // [1, 2, 3, ...]
            var data = (byte[])original.Clone();
            var buffer = new byte[SpmBlockCipher.BlockSizeBytes];

            SpmBlockCipher.s_ApplyPermutation(data, 0, permutation, buffer);

            // s_ApplyPermutation sets: buffer[permutation[k]] = data[k]
            //   permutation[0] = 1  →  buffer[1] = original[0]
            //   permutation[1] = 0  →  buffer[0] = original[1]
            Assert.AreEqual(original[1], data[0], "First byte should be swapped with second.");
            Assert.AreEqual(original[0], data[1], "Second byte should be swapped with first.");
            for (int i = 2; i < original.Length; i++)
                Assert.AreEqual(original[i], data[i], $"Byte {i} should be unchanged.");
        }

        [TestMethod()]
        public void ApplyPermutation_ApplyThenInversePermutation_RestoresData()
        {
            int n = (int)SpmBlockCipher.BlockSizeBytes;
            // Non-trivial permutation: reverse the entire block.
            var permutation = Enumerable.Range(0, n).Select(i => (byte)(n - 1 - i)).ToArray();

            // Build the inverse permutation: inversePermutation[permutation[i]] = i.
            var inversePermutation = new byte[n];
            for (int i = 0; i < n; i++)
                inversePermutation[permutation[i]] = (byte)i;

            var original = MakeTestBlock();
            var data = (byte[])original.Clone();
            var buffer = new byte[n];

            SpmBlockCipher.s_ApplyPermutation(data, 0, permutation, buffer);
            SpmBlockCipher.s_ApplyPermutation(data, 0, inversePermutation, buffer);

            Assert.IsTrue(data.SequenceEqual(original),
                "Applying a permutation followed by its inverse should restore the original data.");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // s_ReverseSmForwardPass
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void DecryptForwardPass_DecrementsMaskIndexByBlockInflectionIndex()
        {
            // s_ReverseSmForwardPass iterates k = 0 .. BlockInflectionIndex-1 (127 steps)
            // and decrements maskIndex once per step.  Starting at BlockInflectionIndex
            // (127) it must reach 0 after the loop.

            int count= (int)SpmBlockCipher.BlockInflectionIndex;
            var data = new byte[SpmBlockCipher.BlockSizeBytes];
            var masks = new ushort[count];
            int maskIndex = count;

            SpmBlockCipher.s_ReverseSmForwardPass(data, 0, BuildIdentitySbox(), masks, ref maskIndex);

            Assert.AreEqual(0, maskIndex,
                $"s_ReverseSmForwardPass should decrement maskIndex by {count}.");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // s_ReverseSmReversePass
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void DecryptReversePass_DecrementsMaskIndexByBlockInflectionIndexMinusOne()
        {
            // s_ReverseSmReversePass iterates k = BlockInflectionIndex-2 down to 0 (126 steps)
            // and decrements maskIndex once per step.

            int count= (int)SpmBlockCipher.BlockInflectionIndex - 1;
            var data = new byte[SpmBlockCipher.BlockSizeBytes];
            var masks = new ushort[count];
            int maskIndex = count;

            SpmBlockCipher.s_ReverseSmReversePass(data, 0, BuildIdentitySbox(), masks, ref maskIndex);

            Assert.AreEqual(0, maskIndex,
                $"s_ReverseSmReversePass should decrement maskIndex by {count}.");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // Combined round-trip: one full encrypt round undone by the two decrypt passes
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void DecryptForwardAndReversePasses_TogetherUndoEncryptForwardAndReversePasses()
        {
            // One encrypt round = s_SmForwardPass (127 mask steps) + s_SmReversePass
            // (126 mask steps) = 253 mask steps total.
            //
            // The Decrypt algorithm pre-collects all masks from the PRNG in their
            // production order, then calls s_ReverseSmForwardPass and s_ReverseSmReversePass
            // with a maskIndex that starts at 253 and walks backwards.  This reverses
            // the full encrypt sequence and restores the original plaintext.

            var sbox= BuildIdentitySbox();
            int totalMasks = (int)(2 * SpmBlockCipher.BlockInflectionIndex - 1); // 253

            // Pre-collect all masks the PRNG will produce during encryption.
            var collectPrng = BuildPrng();
            var masks = new ushort[totalMasks];
            for (int i = 0; i < totalMasks; i++)
                masks[i] = collectPrng.Rand();

            // Encrypt with a fresh, identically-seeded PRNG.
            var original = MakeTestBlock();
            var data = (byte[])original.Clone();
            var encryptPrng = BuildPrng();
            SpmBlockCipher.s_SmForwardPass(data, 0, sbox, encryptPrng);
            SpmBlockCipher.s_SmReversePass(data, 0, sbox, encryptPrng);

            // Decrypt by walking the pre-collected mask array backwards.
            int maskIndex = totalMasks;
            SpmBlockCipher.s_ReverseSmForwardPass(data, 0, sbox, masks, ref maskIndex);
            SpmBlockCipher.s_ReverseSmReversePass(data, 0, sbox, masks, ref maskIndex);

            Assert.IsTrue(data.SequenceEqual(original),
                "s_ReverseSmForwardPass + s_ReverseSmReversePass should exactly undo s_SmForwardPass + s_SmReversePass.");
            Assert.AreEqual(0, maskIndex, "All pre-collected masks should have been consumed.");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // s_EncryptRound
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void EncryptRound_WithPermutation_TransformsDataDifferentlyFromNoPermutation()
        {
            var sbox = BuildIdentitySbox();
            var original = MakeTestBlock();

            // Encrypt with no permutation.
            var dataNoPerms = (byte[])original.Clone();
            var buffer = new byte[SpmBlockCipher.BlockSizeBytes];
            SpmBlockCipher.s_EncryptRound(dataNoPerms, 0, sbox, BuildPrng(), null, buffer);

            // Build a non-identity permutation (reverse).
            int n = (int)SpmBlockCipher.BlockSizeBytes;
            var permutation = Enumerable.Range(0, n).Select(i => (byte)(n - 1 - i)).ToArray();

            // Encrypt with the same data and same PRNG seed but with a permutation.
            var dataWithPerms = (byte[])original.Clone();
            SpmBlockCipher.s_EncryptRound(dataWithPerms, 0, sbox, BuildPrng(), permutation, buffer);

            // The permutation step shuffles bytes after the cipher passes, so the result
            // must differ from the no-permutation case.
            Assert.IsFalse(dataNoPerms.SequenceEqual(dataWithPerms),
                "s_EncryptRound with a non-identity permutation should produce different output than without.");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // Decomposed Encrypt / Decrypt round-trip using the same key, codebook,
        // and test data as SpmBlockCipherTests.EncryptDecryptTest
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void DecomposedEncryptDecryptTest()
        {
            byte[] key = Util.ParsePassword("P@s$w0rd!", SpmBlockCipher.GetKeyWidth());
            Assert.IsTrue(SpmBlockCipher.s_ValidKey(key));

            // Build the same state that SetKeys produces: two PRNGs (sbox + mask),
            // an sbox/reverseSbox pair, and a block permutation table.
            int prngKeyWidth = (int)SimplePrng.GetKeyWidth();

            var encSboxPrng = new SimplePrng();
            encSboxPrng.SetKeys(key, 0);
            var encMaskPrng = new SimplePrng();
            encMaskPrng.SetKeys(key, prngKeyWidth);

            var sbox = new ushort[SpmBlockCipher.SPM_SBOX_WIDTH];
            var reverseSbox = new ushort[SpmBlockCipher.SPM_SBOX_WIDTH];
            var blockPermutation = new byte[SpmBlockCipher.BlockSizeBytes];

            SpmBlockCipher.s_InitSbox(sbox, SpmBlockCipher.CodeBook, blockPermutation, SpmBlockCipher.PermutationCodeBook);
            SpmBlockCipher.s_PermuteSbox(sbox, reverseSbox, blockPermutation, encSboxPrng);

            // Prepare the same two-block test data used by EncryptDecryptTest.
            var testData = new byte[SpmBlockCipher.BlockSizeBytes * 2];
            System.Text.Encoding.UTF8.GetBytes("Block 1").CopyTo(testData, 0);
            System.Text.Encoding.UTF8.GetBytes("Block 2").CopyTo(testData, (int)SpmBlockCipher.BlockSizeBytes);

            var buffer = new byte[SpmBlockCipher.BlockSizeBytes * 2];
            testData.CopyTo(buffer, 0);

            DecomposedEncrypt(buffer, sbox, encSboxPrng, encMaskPrng, blockPermutation);

            // Validate the encrypted output matches the known regression value.
            byte[] expected = Util.HexToBin(TestConstants.ExpectedEncryptOutput);
            Assert.IsTrue(buffer.SequenceEqual(expected),
                $"Decomposed encryption output does not match expected.\nGot: {Util.Bin2Hex(buffer)}");

            // Now decrypt using the same decomposed approach with a fresh set of PRNGs
            // seeded identically (mirroring what Decrypt does with the same key).
            var decSboxPrng = new SimplePrng();
            decSboxPrng.SetKeys(key, 0);
            var decMaskPrng = new SimplePrng();
            decMaskPrng.SetKeys(key, prngKeyWidth);

            var decSbox = new ushort[SpmBlockCipher.SPM_SBOX_WIDTH];
            var decReverseSbox = new ushort[SpmBlockCipher.SPM_SBOX_WIDTH];
            var decBlockPermutation = new byte[SpmBlockCipher.BlockSizeBytes];

            SpmBlockCipher.s_InitSbox(decSbox, SpmBlockCipher.CodeBook, decBlockPermutation, SpmBlockCipher.PermutationCodeBook);
            SpmBlockCipher.s_PermuteSbox(decSbox, decReverseSbox, decBlockPermutation, decSboxPrng);

            DecomposedDecrypt(buffer, decReverseSbox, decSboxPrng, decMaskPrng, decBlockPermutation);

            Assert.IsTrue(buffer.SequenceEqual(testData),
                "Decomposed decrypt should restore the original plaintext.");
        }

        /// <summary>
        /// Encrypts data block-by-block using the individual static helper methods,
        /// mirroring the logic of SpmBlockCipher.Encrypt.
        /// </summary>
        private static void DecomposedEncrypt(byte[] data, ushort[] sbox, SimplePrng sboxPrng, SimplePrng maskPrng, byte[] blockPermutation)
        {
            var permutationBuffer = new byte[SpmBlockCipher.BlockSizeBytes];

            for (int i = 0; i < data.Length; i += (int)SpmBlockCipher.BlockSizeBytes)
            {
                // Per-block permutation shuffle (same as ShuffleBlockPermutation)
                byte[] perm = SpmBlockCipher.s_ShuffleBlockPermutation(blockPermutation, sboxPrng);

                // 3 rounds per block
                for (int round = 0; round < 3; round++)
                {
                    SpmBlockCipher.s_SmForwardPass(data, i, sbox, maskPrng);
                    SpmBlockCipher.s_SmReversePass(data, i, sbox, maskPrng);
                    SpmBlockCipher.s_ApplyPermutation(data, i, perm, permutationBuffer);
                }
            }
        }

        /// <summary>
        /// Decrypts data block-by-block using the individual static helper methods,
        /// mirroring the logic of SpmBlockCipher.Decrypt.
        /// </summary>
        private static void DecomposedDecrypt(byte[] data, ushort[] reverseSbox, SimplePrng sboxPrng, SimplePrng maskPrng, byte[] blockPermutation)
        {
            var permutationBuffer = new byte[SpmBlockCipher.BlockSizeBytes];
            int masksPerRound = (int)(2 * SpmBlockCipher.BlockInflectionIndex - 1);

            for (int i = 0; i < data.Length; i += (int)SpmBlockCipher.BlockSizeBytes)
            {
                // Per-block: compute the shuffled permutation, then its inverse
                byte[] perm = SpmBlockCipher.s_ShuffleBlockPermutation(blockPermutation, sboxPrng);
                var reversePerm = new byte[SpmBlockCipher.BlockSizeBytes];
                for (int k = 0; k < perm.Length; k++)
                    reversePerm[perm[k]] = (byte)k;

                // Pre-collect all masks for 3 rounds (same order maskPrng would produce)
                var masks = new ushort[3 * masksPerRound];
                for (int m = 0; m < masks.Length; m++)
                    masks[m] = maskPrng.Rand();

                // Decrypt rounds in reverse order (round 2, 1, 0)
                int maskIndex = masks.Length;
                for (int round = 2; round >= 0; round--)
                {
                    SpmBlockCipher.s_ApplyPermutation(data, i, reversePerm, permutationBuffer);
                    SpmBlockCipher.s_ReverseSmForwardPass(data, i, reverseSbox, masks, ref maskIndex);
                    SpmBlockCipher.s_ReverseSmReversePass(data, i, reverseSbox, masks, ref maskIndex);
                }
            }
        }
    }
}
