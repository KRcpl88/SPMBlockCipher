using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace Spm.Tests
{
    [TestClass()]
    public class SpmBlockCipherTests
    {
        [TestMethod()]
        public void EncryptDecryptTest()
        {
            byte[] key = null;

            SpmBlockCipher.PrintCipherName();

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

            TestEncryption(encryptor, decryptor, 0x8b, 0xdb,
                TestConstants.ExpectedEncryptOutput);
        }

        private static void TestEncryption(SpmBlockCipher encryptor, SpmBlockCipher decryptor, byte firstByte, byte lastByte, string expectedHex = null)
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

            if (expectedHex != null)
            {
                byte[] expected = Util.HexToBin(expectedHex);
                int fullMatch = CompareBytes(expected, buffer);
                Assert.IsTrue(fullMatch == buffer.Length,
                    $"Encryption output regression: expected {expectedHex} but got {Util.Bin2Hex(buffer)}");
            }

            decryptor.Decrypt(buffer);
            matchCount = CompareBytes(testData, buffer);

            Assert.IsTrue(matchCount == testData.Length);
        }

        [TestMethod()]
        public void ApplyNonceTest()
        {
            byte[] nonce = Util.HexToBin("3cd20273b6a4c072764b0bc79c14314b2233db9c230bc32aa37b6a4469c2bc79");
            Assert.IsTrue(nonce.Length == SpmBlockCipher.GetKeyWidth());

            byte[] key = Util.ParsePassword("P@s$w0rd!", SpmBlockCipher.GetKeyWidth());
            Assert.IsTrue(key.Length == SpmBlockCipher.GetKeyWidth());
            Assert.IsTrue(SpmBlockCipher.s_ValidKey(key));

            var encryptor = new SpmBlockCipher();
            var decryptor = new SpmBlockCipher();

            Util.ApplyNonce(nonce, key, encryptor);
            Util.ApplyNonce(nonce, key, decryptor);

            TestEncryption(encryptor, decryptor, 0xe0, 0xfa,
                "E00D98786D3CFED49DD871ED28AF0FB12F79DAA5B92DF63705E12EC34A4445B0D54B29DF198F96974F360F20945C66783B1B8514FDC8B1F704CF99DD58705EC2AACF9F7C8D1D32FC29572B590D663D8F55AC3A15094276FF4110280AA59656122C603A4959BE704630C1DC8C9970E4393F80DE6FD0770478B8BFAE7955FADFFBD4BC2A3C3D9D3F6A82B05836BD943D450F745DE39E4F7535BCEF281EED6E51585F8E28EB5E0E91252ACE069D331F68F359A333902FFBCA3D7890603F893ED9A846D5C768824FE69A28BE0FB07A70DC9A5E2CDF11A736719CE477D272EBD27BC40C0B20FB0C862D389560029E6FAEC40ED73D2B026C1A7E91CADF6F49FE5E99FA");
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
                Assert.IsTrue(matchCount < 6, $"{matchCount} bytes did not change");
            }
        }
    }
}