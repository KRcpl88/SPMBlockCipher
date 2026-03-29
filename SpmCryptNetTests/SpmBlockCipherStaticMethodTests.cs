using Microsoft.VisualStudio.TestTools.UnitTesting;
using Spm;
using System.Linq;

namespace Spm.Tests
{
    /// <summary>
    /// Unit tests for the five static methods added to SpmBlockCipher:
    /// EncryptForwardPass, EncryptReversePass, ApplyPermutation,
    /// DecryptForwardPass, and DecryptReversePass.
    /// </summary>
    [TestClass()]
    public class SpmBlockCipherStaticMethodTests
    {
        private const string TestCodebookKey = "b6a4c072764a2233db9c23b0bc79c143";

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
        // EncryptForwardPass
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void EncryptForwardPass_TransformsData()
        {
            SpmBlockCipher.InitCodebook(TestCodebookKey, SpmBlockCipher.BLOCK_MODE.Permutation);
            var original = MakeTestBlock();
            var data = (byte[])original.Clone();

            SpmBlockCipher.EncryptForwardPass(data, 0, BuildIdentitySbox(), BuildPrng());

            Assert.IsFalse(data.SequenceEqual(original),
                "EncryptForwardPass should change the data.");
        }

        [TestMethod()]
        public void EncryptForwardPass_AppliedTwiceWithSameKey_RestoresOriginalData()
        {
            // With an identity s-box, EncryptForwardPass applies overlapping 2-byte XOR
            // windows in forward order (k = 0 .. BlockInflectionIndex-1).  Because each
            // step reads byte k+1 which may have been written by the previous step, the
            // second application (with the identically-seeded PRNG) restores the original
            // data: the "involution" property can be verified by induction on k.
            SpmBlockCipher.InitCodebook(TestCodebookKey, SpmBlockCipher.BLOCK_MODE.Permutation);

            var sbox = BuildIdentitySbox();
            var original = MakeTestBlock();
            var data = (byte[])original.Clone();

            SpmBlockCipher.EncryptForwardPass(data, 0, sbox, BuildPrng());
            SpmBlockCipher.EncryptForwardPass(data, 0, sbox, BuildPrng()); // identical seed → identical masks

            Assert.IsTrue(data.SequenceEqual(original),
                "Applying EncryptForwardPass twice with the same key should restore the original data.");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // EncryptReversePass
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void EncryptReversePass_TransformsData()
        {
            SpmBlockCipher.InitCodebook(TestCodebookKey, SpmBlockCipher.BLOCK_MODE.Permutation);
            var original = MakeTestBlock();
            var data = (byte[])original.Clone();

            SpmBlockCipher.EncryptReversePass(data, 0, BuildIdentitySbox(), BuildPrng());

            Assert.IsFalse(data.SequenceEqual(original),
                "EncryptReversePass should change the data.");
        }

        [TestMethod()]
        public void EncryptReversePass_AppliedTwiceWithSameKey_RestoresOriginalData()
        {
            // Same involution property as EncryptForwardPass, but the window iterates
            // in reverse order (k = BlockInflectionIndex-2 down to 0).
            SpmBlockCipher.InitCodebook(TestCodebookKey, SpmBlockCipher.BLOCK_MODE.Permutation);

            var sbox = BuildIdentitySbox();
            var original = MakeTestBlock();
            var data = (byte[])original.Clone();

            SpmBlockCipher.EncryptReversePass(data, 0, sbox, BuildPrng());
            SpmBlockCipher.EncryptReversePass(data, 0, sbox, BuildPrng()); // identical seed → identical masks

            Assert.IsTrue(data.SequenceEqual(original),
                "Applying EncryptReversePass twice with the same key should restore the original data.");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // ApplyPermutation
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void ApplyPermutation_IdentityPermutation_LeavesDataUnchanged()
        {
            var permutation = Enumerable.Range(0, (int)SpmBlockCipher.BlockSizeBytes)
                .Select(i => (byte)i).ToArray();
            var original = MakeTestBlock();
            var data = (byte[])original.Clone();
            var buffer = new byte[SpmBlockCipher.BlockSizeBytes];

            SpmBlockCipher.ApplyPermutation(data, 0, permutation, buffer);

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

            SpmBlockCipher.ApplyPermutation(data, 0, permutation, buffer);

            // ApplyPermutation sets: buffer[permutation[k]] = data[k]
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

            SpmBlockCipher.ApplyPermutation(data, 0, permutation, buffer);
            SpmBlockCipher.ApplyPermutation(data, 0, inversePermutation, buffer);

            Assert.IsTrue(data.SequenceEqual(original),
                "Applying a permutation followed by its inverse should restore the original data.");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // DecryptForwardPass
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void DecryptForwardPass_DecrementsMaskIndexByBlockInflectionIndex()
        {
            // DecryptForwardPass iterates k = 0 .. BlockInflectionIndex-1 (127 steps)
            // and decrements maskIndex once per step.  Starting at BlockInflectionIndex
            // (127) it must reach 0 after the loop.
            SpmBlockCipher.InitCodebook(TestCodebookKey, SpmBlockCipher.BLOCK_MODE.Permutation);

            int count = (int)SpmBlockCipher.BlockInflectionIndex;
            var data = new byte[SpmBlockCipher.BlockSizeBytes];
            var masks = new ushort[count];
            int maskIndex = count;

            SpmBlockCipher.DecryptForwardPass(data, 0, BuildIdentitySbox(), masks, ref maskIndex);

            Assert.AreEqual(0, maskIndex,
                $"DecryptForwardPass should decrement maskIndex by {count}.");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // DecryptReversePass
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void DecryptReversePass_DecrementsMaskIndexByBlockInflectionIndexMinusOne()
        {
            // DecryptReversePass iterates k = BlockInflectionIndex-2 down to 0 (126 steps)
            // and decrements maskIndex once per step.
            SpmBlockCipher.InitCodebook(TestCodebookKey, SpmBlockCipher.BLOCK_MODE.Permutation);

            int count = (int)SpmBlockCipher.BlockInflectionIndex - 1;
            var data = new byte[SpmBlockCipher.BlockSizeBytes];
            var masks = new ushort[count];
            int maskIndex = count;

            SpmBlockCipher.DecryptReversePass(data, 0, BuildIdentitySbox(), masks, ref maskIndex);

            Assert.AreEqual(0, maskIndex,
                $"DecryptReversePass should decrement maskIndex by {count}.");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // Combined round-trip: one full encrypt round undone by the two decrypt passes
        // ──────────────────────────────────────────────────────────────────────────

        [TestMethod()]
        public void DecryptForwardAndReversePasses_TogetherUndoEncryptForwardAndReversePasses()
        {
            // One encrypt round = EncryptForwardPass (127 mask steps) + EncryptReversePass
            // (126 mask steps) = 253 mask steps total.
            //
            // The Decrypt algorithm pre-collects all masks from the PRNG in their
            // production order, then calls DecryptForwardPass and DecryptReversePass
            // with a maskIndex that starts at 253 and walks backwards.  This reverses
            // the full encrypt sequence and restores the original plaintext.
            SpmBlockCipher.InitCodebook(TestCodebookKey, SpmBlockCipher.BLOCK_MODE.Permutation);

            var sbox = BuildIdentitySbox();
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
            SpmBlockCipher.EncryptForwardPass(data, 0, sbox, encryptPrng);
            SpmBlockCipher.EncryptReversePass(data, 0, sbox, encryptPrng);

            // Decrypt by walking the pre-collected mask array backwards.
            int maskIndex = totalMasks;
            SpmBlockCipher.DecryptForwardPass(data, 0, sbox, masks, ref maskIndex);
            SpmBlockCipher.DecryptReversePass(data, 0, sbox, masks, ref maskIndex);

            Assert.IsTrue(data.SequenceEqual(original),
                "DecryptForwardPass + DecryptReversePass should exactly undo EncryptForwardPass + EncryptReversePass.");
            Assert.AreEqual(0, maskIndex, "All pre-collected masks should have been consumed.");
        }
    }
}
