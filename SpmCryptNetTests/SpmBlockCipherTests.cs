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

            var encPrngState = encryptor.GetPrngStateKeys();
            Assert.IsTrue(encPrngState[0] == 0x2FC1CF3A7257322FUL); // encryptor sboxPrng state
            Assert.IsTrue(encPrngState[1] == 0x7230772473405021UL); // encryptor sboxPrng key
            Assert.IsTrue(encPrngState[2] == 4UL);                  // encryptor sboxPrng idx
            Assert.IsTrue(encPrngState[3] == 0x3077247340502164UL); // encryptor maskPrng state
            Assert.IsTrue(encPrngState[4] == 0x7724734050216473UL); // encryptor maskPrng key
            Assert.IsTrue(encPrngState[5] == 0UL);                  // encryptor maskPrng idx

            var decPrngState = decryptor.GetPrngStateKeys();
            Assert.IsTrue(decPrngState[0] == 0x2FC1CF3A7257322FUL); // decryptor sboxPrng state
            Assert.IsTrue(decPrngState[1] == 0x7230772473405021UL); // decryptor sboxPrng key
            Assert.IsTrue(decPrngState[2] == 4UL);                  // decryptor sboxPrng idx
            Assert.IsTrue(decPrngState[3] == 0x3077247340502164UL); // decryptor maskPrng state
            Assert.IsTrue(decPrngState[4] == 0x7724734050216473UL); // decryptor maskPrng key
            Assert.IsTrue(decPrngState[5] == 0UL);                  // decryptor maskPrng idx

            TestEncryption(encryptor, decryptor,
                TestConstants.ExpectedEncryptOutput);
        }

        private static void TestEncryption(SpmBlockCipher encryptor, SpmBlockCipher decryptor, string expectedHex = null)
        {
            int matchCount;

            var testData = new byte[SpmBlockCipher.BlockSizeBytes * 2];
            System.Text.Encoding.UTF8.GetBytes("Block 1        |               |               |               |               |               |               |               |")
                .CopyTo(testData, 0);
            System.Text.Encoding.UTF8.GetBytes("Block 2        |               |               |               |               |               |               |               |")
                .CopyTo(testData, (int)SpmBlockCipher.BlockSizeBytes);

            var buffer = new byte[testData.Length];
            testData.CopyTo(buffer, 0);
            encryptor.Encrypt(buffer);
            matchCount = CompareBytes(testData, buffer);

            Assert.IsTrue(matchCount < 4);

            if (expectedHex != null)
            {
                byte[] expected = Util.HexToBin(expectedHex);

                Assert.IsTrue(buffer.Length == expected.Length,
                    $"Decomposed encryption output length does not match expected.\nGot: {buffer.Length}"); 

                Assert.IsTrue(((ReadOnlySpan<byte>)buffer).SequenceEqual(expected),
                    $"Decomposed encryption output does not match expected.\nGot: {Util.Bin2Hex(buffer)}");                

            }

            decryptor.Decrypt(buffer);
            matchCount = CompareBytes(testData, buffer);

            Assert.IsTrue(matchCount == testData.Length);
        }

        [TestMethod()]
        public void ApplyNonceTest()
        {
            byte[] nonce = Util.HexToBin("3cd20273b6a4c072764b0bc79c14314b2233db9c230bc32aa37b6a4469c2bc79000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
            Assert.IsTrue(nonce.Length == SpmBlockCipher.BlockSizeBytes);

            byte[] key = Util.ParsePassword("P@s$w0rd!", SpmBlockCipher.GetKeyWidth());
            Assert.IsTrue(key.Length == SpmBlockCipher.GetKeyWidth());
            Assert.IsTrue(SpmBlockCipher.s_ValidKey(key));

            var encryptor = new SpmBlockCipher();
            var decryptor = new SpmBlockCipher();

            Util.ApplyNonce(nonce, key, encryptor);
            Util.ApplyNonce(nonce, key, decryptor);

            TestEncryption(encryptor, decryptor,
                "802E3D2D5F801EB87F58020BDAAA478A17A6E8D90F654293C0C0C2FC2B02AB7ECB0E2C61147FBDE06F76A75E519AA5B2B5E829E83DCF758EABD9E2A372FE7BF45185848FA91D82D3F66BCE67C2F3A1B7CBE80DCB2102FF69C80D1F54C2E08DD561BFA544C1968A30AEDA2389281647618546A99BE2F283D13628D1ADFCE5DF032ED00A47D1A2320A912464F9FEF727848966D29F52656BF34EAFE1121ECAACA51802EA9E538ADE756136819CA704D8CB96C94211B60B4C7D949549732081B659960D7D1BDC0B1F770346826378081D1D1BC9EDB0F826260A1FC8CF4FBA3ADFF369BE67314CF897437460B4DA6A19E9973B44E7D9781FB5AFB3F8A034B905BB36");
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