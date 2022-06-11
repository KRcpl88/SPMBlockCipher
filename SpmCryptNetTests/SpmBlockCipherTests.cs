using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace Spm.Tests
{
    [TestClass()]
    public class SpmBlockCipherTests
    {
        [TestMethod()]
        public void PermutationEncryptTest()
        {
            byte[] key = null;
            int retval = 0;

            SpmBlockCipher.PrintCipherName();

            retval = SpmBlockCipher.InitCodebook("b6a4c072764a2233db9c23b0bc79c143", SpmBlockCipher.BLOCK_MODE.Permutation);
            Assert.IsTrue(retval == 0);
            Assert.IsTrue(SpmBlockCipher.CodeBook[0] == 0xbe7d);
            Assert.IsTrue(SpmBlockCipher.CodeBook[0xffff] == 0x655c);
            Assert.IsTrue(SpmBlockCipher.PermutationCodeBook != null);
            Assert.IsTrue(SpmBlockCipher.PermutationCodeBook[0] == 0x23);
            Assert.IsTrue(SpmBlockCipher.PermutationCodeBook[SpmBlockCipher.BlockSizeBytes - 1] == 0x2f);

            key = Util.ParsePassword("P@s$w0rd!", SpmBlockCipher.GetKeyWidth());
            Assert.IsTrue(SpmBlockCipher.s_ValidKey(key));

            var encryptor = new SpmBlockCipher();
            var decryptor = new SpmBlockCipher();

            encryptor.SetKeys(key);
            decryptor.SetKeys(key);

            TestEncryption(encryptor, decryptor, 0x10, 0xe5);
        }

        private static void TestEncryption(SpmBlockCipher encryptor, SpmBlockCipher decryptor, byte firstByte, byte lastByte)
        {
            int matchCount;

            var testData = new byte[SpmBlockCipher.BlockSizeBytes * 2];
            Encoding.UTF8.GetBytes("Block 1").CopyTo(testData, 0);
            Encoding.UTF8.GetBytes("Block 2").CopyTo(testData, (int)SpmBlockCipher.BlockSizeBytes);

            var buffer = new byte[SpmBlockCipher.BlockSizeBytes * 2];
            testData.CopyTo(buffer, 0);
            encryptor.Encrypt(buffer);
            matchCount = CompareBytes(testData, buffer);
            Assert.IsTrue(buffer[0] == firstByte);
            Assert.IsTrue(buffer[SpmBlockCipher.BlockSizeBytes * 2 - 1] == lastByte);

            Assert.IsTrue(matchCount < 4);

            decryptor.Decrypt(buffer);
            matchCount = CompareBytes(testData, buffer);

            Assert.IsTrue(matchCount == testData.Length);
        }

        [TestMethod()]
        public void NonceTest()
        {
            SpmBlockCipher.InitCodebook("b6a4c072764a2233db9c23b0bc79c143", SpmBlockCipher.BLOCK_MODE.Permutation);

            byte[] nonce = Util.HexToBin("3cd20273b6a4c072764b0bc79c14314b2233db9c230bc32aa37b6a4469c2bc79");
            Assert.IsTrue(nonce.Length == SpmBlockCipher.GetKeyWidth());

            byte[] key = Util.ParsePassword("P@s$w0rd!", SpmBlockCipher.GetKeyWidth());
            Assert.IsTrue(key.Length == SpmBlockCipher.GetKeyWidth());
            Assert.IsTrue(SpmBlockCipher.s_ValidKey(key));

            var encryptor = new SpmBlockCipher();
            var decryptor = new SpmBlockCipher();

            Util.ApplyNonce(nonce, key, encryptor);
            Util.ApplyNonce(nonce, key, decryptor);

            TestEncryption(encryptor, decryptor, 0x4f, 0x4a);
        }

        private static int CompareBytes(byte[] pTestData, byte[] pBuffer)
        {
            int i;
            int matchCount = 0; 

            for (i = 0; pBuffer.Length > i; ++i)
            {
                if (pBuffer[i] == pTestData[i])
                {
                    ++matchCount;
                }
            }

            return matchCount;
        }

        [TestMethod()]
        public void TestSingleBitFlip()
        {
            int matchCount;
            int i;
            SpmBlockCipher.InitCodebook("b6a4c072764a2233db9c23b0bc79c143", SpmBlockCipher.BLOCK_MODE.Permutation);

            byte[] key;

            for (i=0; 32 > i; ++i)
            {
                key = Util.MakeKey(SpmBlockCipher.GetKeyWidth());
                Console.Write("Key: ");
                Util.PrintBin(key);
                Console.WriteLine();

                Assert.IsTrue(SpmBlockCipher.s_ValidKey(key));

                var encryptor = new SpmBlockCipher();
                encryptor.SetKeys(key);

                Console.WriteLine("Testing block 1");
                var testData1 = Util.HexToBin("0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C");
                encryptor.Encrypt(testData1);

               // now flip 1 bit
                encryptor = new SpmBlockCipher();
                encryptor.SetKeys(key);

                Console.WriteLine("Testing block 2");
                var testData2 = Util.HexToBin("8F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C");

                encryptor.Encrypt(testData2);

                Console.WriteLine("Block 1 encrypted:");
                Util.PrintBin(testData1);
                Console.WriteLine();

                Console.WriteLine("Block 2 encrypted:");
                Util.PrintBin(testData2);
                Console.WriteLine();

                matchCount = CompareBytes(testData1, testData2);
                Assert.IsTrue(matchCount < 6, "{0} bytes did not change", matchCount);
            }
        }
    }
}