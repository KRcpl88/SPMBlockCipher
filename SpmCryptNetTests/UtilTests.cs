using Microsoft.VisualStudio.TestTools.UnitTesting;
using Spm;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Spm.Tests
{
    [TestClass()]
    public class UtilTests
    {
        [TestMethod()]
        public void HexToBinTest()
        {
            byte[] pBin = Util.HexToBin("3f");
            Assert.IsTrue(pBin.Length == 1);
            foreach (byte c in pBin)
            {
                Assert.IsTrue(c == 0x3f);
            }

            pBin = Util.HexToBin("9");
            Assert.IsTrue(pBin.Length == 1);
            foreach (byte c in pBin)
            {
                Assert.IsTrue(c == 9);
            }

            pBin = Util.HexToBin("FFFF");
            Assert.IsTrue(pBin.Length == 2);
            foreach (byte c in pBin)
            {
                Assert.IsTrue(c == 255);
            }

            pBin = Util.HexToBin("FFFFFFFF");
            Assert.IsTrue(pBin.Length == 4);
            foreach (byte c in pBin)
            {
                Assert.IsTrue(c == 255);
            }

            pBin = Util.HexToBin("00000000");
            Assert.IsTrue(pBin.Length == 4);
            foreach (byte c in pBin)
            {
                Assert.IsTrue(c == 0);
            }

            pBin = Util.HexToBin("000");
            Assert.IsTrue(pBin.Length == 2);
            foreach (byte c in pBin)
            {
                Assert.IsTrue(c == 0);
            }

            pBin = Util.HexToBin("101");
            Assert.IsTrue(pBin.Length == 2);
            foreach (byte c in pBin)
            {
                Assert.IsTrue(c == 1);
            }
        }

        [TestMethod()]
        public void NonceTest()
        {
            byte[] nonce = Util.HexToBin("3cd20273b6a4c072764b0bc79c14314b2233db9c230bc32aa37b6a4469c2bc79000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
            Assert.IsTrue(nonce.Length == SpmBlockCipher.BlockSizeBytes);

            byte[] key = Util.ParsePassword("P@s$w0rd!", SpmBlockCipher.GetKeyWidth());
            Assert.IsTrue(SpmBlockCipher.s_ValidKey(key));

            var encryptor = new SpmBlockCipher();
            var decryptor = new SpmBlockCipher();

            Util.ApplyNonce(nonce, key, encryptor);
            Util.ApplyNonce(nonce, key, decryptor);

            byte[] testData = new byte[SpmBlockCipher.BlockSizeBytes];
            for (int idx = 0; idx < testData.Length; idx++) testData[idx] = (byte)(idx + 1);
            byte[] buf = (byte[])testData.Clone();

            encryptor.Encrypt(buf);
            Assert.IsFalse(buf.SequenceEqual(testData));

            decryptor.Decrypt(buf);
            Assert.IsTrue(buf.SequenceEqual(testData));
        }

        [TestMethod()]
        public void ApplyNonce_DifferentNoncesProduceDifferentEncryptionTest()
        {
            byte[] nonce1= Util.HexToBin("3cd20273b6a4c072764b0bc79c14314b2233db9c230bc32aa37b6a4469c2bc79000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
            byte[] nonce2 = Util.HexToBin("4cd20273b6a4c072764b0bc79c14314b2233db9c230bc32aa37b6a4469c2bc79000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
            byte[] key = Util.ParsePassword("P@s$w0rd!", SpmBlockCipher.GetKeyWidth());

            byte[] testData = new byte[SpmBlockCipher.BlockSizeBytes];
            for (int idx = 0; idx < testData.Length; idx++) testData[idx] = (byte)(idx + 1);

            var encryptor1 = new SpmBlockCipher();
            Util.ApplyNonce(nonce1, key, encryptor1);
            byte[] buf1 = (byte[])testData.Clone();
            encryptor1.Encrypt(buf1);

            var encryptor2 = new SpmBlockCipher();
            Util.ApplyNonce(nonce2, key, encryptor2);
            byte[] buf2 = (byte[])testData.Clone();
            encryptor2.Encrypt(buf2);

            Assert.IsFalse(buf1.SequenceEqual(buf2));
        }

        [TestMethod()]
        public void GenNonceFromInputTest()
        {
            var originalIn = Console.In;
            Console.SetIn(new StringReader("\n"));
            byte[] nonce = Util.GenNonceFromInput();
            Console.SetIn(originalIn);

            Assert.IsNotNull(nonce);
            Assert.IsTrue(nonce.Length == SpmBlockCipher.BlockSizeBytes);
        }

        [TestMethod()]
        public void GenNonceFromInput_CustomHashKeyTest()
        {
            byte[] hashKey = Util.HexToBin("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789");

            var originalIn = Console.In;
            Console.SetIn(new StringReader("\n"));
            byte[] nonce = Util.GenNonceFromInput(hashKey);
            Console.SetIn(originalIn);

            Assert.IsNotNull(nonce);
            Assert.IsTrue(nonce.Length == SpmBlockCipher.BlockSizeBytes);
        }

        [TestMethod()]
        public void GenNonceFromInput_UniqueNoncesTest()
        {
            var originalIn = Console.In;

            Console.SetIn(new StringReader("\n"));
            byte[] nonce1 = Util.GenNonceFromInput();

            Console.SetIn(new StringReader("\n"));
            byte[] nonce2 = Util.GenNonceFromInput();

            Console.SetIn(originalIn);

            Assert.IsNotNull(nonce1);
            Assert.IsNotNull(nonce2);
            Assert.IsFalse(nonce1.SequenceEqual(nonce2));
        }

        [TestMethod()]
        public void ParsePasswordTest_OutputLengthMatchesCb()
        {
            byte[] key16 = Util.ParsePassword("password", 16);
            Assert.IsTrue(key16.Length == 16);

            byte[] key32 = Util.ParsePassword("password", SpmBlockCipher.GetKeyWidth());
            Assert.IsTrue(key32.Length == SpmBlockCipher.GetKeyWidth());

            byte[] key1 = Util.ParsePassword("password", 1);
            Assert.IsTrue(key1.Length == 1);
        }

        [TestMethod()]
        public void ParsePasswordTest_Deterministic()
        {
            byte[] key1 = Util.ParsePassword("P@s$w0rd!", SpmBlockCipher.GetKeyWidth());
            byte[] key2 = Util.ParsePassword("P@s$w0rd!", SpmBlockCipher.GetKeyWidth());

            Assert.IsNotNull(key1);
            Assert.IsNotNull(key2);
            Assert.IsTrue(key1.SequenceEqual(key2));
        }

        [TestMethod()]
        public void ParsePasswordTest_SingleCharFillsArray()
        {
            // Single-char password: every output byte should equal the char's byte value
            // "A" = 0x41; filling 4 bytes → [0x41, 0x41, 0x41, 0x41]
            byte[] key = Util.ParsePassword("A", 4);
            Assert.IsTrue(key.Length == 4);
            foreach (byte b in key)
            {
                Assert.IsTrue(b == (byte)'A');
            }
        }

        [TestMethod()]
        public void ParsePasswordTest_PasswordLengthEqualsCb()
        {
            // "AB" with cb=2: one pass, no wrapping → [0x41, 0x42]
            byte[] key = Util.ParsePassword("AB", 2);
            Assert.IsTrue(key.Length == 2);
            Assert.IsTrue(key[0] == (byte)'A');
            Assert.IsTrue(key[1] == (byte)'B');
        }

        [TestMethod()]
        public void ParsePasswordTest_PasswordShorterThanCb()
        {
            // "AB" with cb=4: password wraps → [0x41, 0x42, 0x41, 0x42]
            byte[] key = Util.ParsePassword("AB", 4);
            Assert.IsTrue(key.Length == 4);
            Assert.IsTrue(key[0] == (byte)'A');
            Assert.IsTrue(key[1] == (byte)'B');
            Assert.IsTrue(key[2] == (byte)'A');
            Assert.IsTrue(key[3] == (byte)'B');
        }

        [TestMethod()]
        public void ParsePasswordTest_PasswordLongerThanCb()
        {
            // "ABCD" with cb=3: first pass fills [A,B,C], second pass adds D to bin[0]
            // → [A+D, B, C] = [0x41+0x44, 0x42, 0x43] = [0x85, 0x42, 0x43]
            byte[] key = Util.ParsePassword("ABCD", 3);
            Assert.IsTrue(key.Length == 3);
            Assert.IsTrue(key[0] == (byte)'A' + (byte)'D');
            Assert.IsTrue(key[1] == (byte)'B');
            Assert.IsTrue(key[2] == (byte)'C');
        }

        [TestMethod()]
        public void ParsePasswordTest_DifferentPasswordsDifferentOutput()
        {
            byte[] key1 = Util.ParsePassword("password1", SpmBlockCipher.GetKeyWidth());
            byte[] key2 = Util.ParsePassword("password2", SpmBlockCipher.GetKeyWidth());

            Assert.IsNotNull(key1);
            Assert.IsNotNull(key2);
            Assert.IsFalse(key1.SequenceEqual(key2));
        }

        [TestMethod()]
        public void FbcEncryptDecryptFileTest()
        {
            string plaintextFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string ciphertextFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string decryptedFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

            try
            {
                byte[] originalContent = System.Text.Encoding.UTF8.GetBytes("Hello, SPM Block Cipher! This is a short plaintext file for testing.");
                File.WriteAllBytes(plaintextFile, originalContent);

                byte[] key = Util.ParsePassword("P@s$w0rd!", SpmBlockCipher.GetKeyWidth());

                Util.FbcEncryptFile(plaintextFile, ciphertextFile, key);
                Util.FbcDecryptFile(ciphertextFile, decryptedFile, key);

                byte[] decryptedContent = File.ReadAllBytes(decryptedFile);

                Assert.IsTrue(decryptedContent.SequenceEqual(originalContent),
                    "Decrypted file content does not match original plaintext.");
            }
            finally
            {
                if (File.Exists(plaintextFile)) File.Delete(plaintextFile);
                if (File.Exists(ciphertextFile)) File.Delete(ciphertextFile);
                if (File.Exists(decryptedFile)) File.Delete(decryptedFile);
            }
        }

    }
}