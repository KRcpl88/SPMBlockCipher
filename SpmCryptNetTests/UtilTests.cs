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
        public void ApplyNonceTest()
        {
            SpmBlockCipher.InitCodebook("b6a4c072764a2233db9c23b0bc79c143", SpmBlockCipher.BLOCK_MODE.Permutation);

            byte[] nonce = Util.HexToBin("3cd20273b6a4c072764b0bc79c14314b2233db9c230bc32aa37b6a4469c2bc79");
            Assert.IsTrue(nonce.Length == SpmBlockCipher.GetKeyWidth());

            byte[] key = Util.ParsePassword("P@s$w0rd!", SpmBlockCipher.GetKeyWidth());
            Assert.IsTrue(SpmBlockCipher.s_ValidKey(key));

            var encryptor = new SpmBlockCipher();
            var decryptor = new SpmBlockCipher();

            Util.ApplyNonce(nonce, key, encryptor);
            Util.ApplyNonce(nonce, key, decryptor);

            byte[] testData = Util.HexToBin("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20");
            byte[] buf = (byte[])testData.Clone();

            encryptor.Encrypt(buf);
            Assert.IsFalse(buf.SequenceEqual(testData));

            decryptor.Decrypt(buf);
            Assert.IsTrue(buf.SequenceEqual(testData));
        }

        [TestMethod()]
        public void ApplyNonce_DifferentNoncesProduceDifferentEncryptionTest()
        {
            SpmBlockCipher.InitCodebook("b6a4c072764a2233db9c23b0bc79c143", SpmBlockCipher.BLOCK_MODE.Permutation);

            byte[] nonce1 = Util.HexToBin("3cd20273b6a4c072764b0bc79c14314b2233db9c230bc32aa37b6a4469c2bc79");
            byte[] nonce2 = Util.HexToBin("4cd20273b6a4c072764b0bc79c14314b2233db9c230bc32aa37b6a4469c2bc79");
            byte[] key = Util.ParsePassword("P@s$w0rd!", SpmBlockCipher.GetKeyWidth());

            byte[] testData = Util.HexToBin("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20");

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
            SpmBlockCipher.InitCodebook("b6a4c072764a2233db9c23b0bc79c143", SpmBlockCipher.BLOCK_MODE.Permutation);

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
            SpmBlockCipher.InitCodebook("b6a4c072764a2233db9c23b0bc79c143", SpmBlockCipher.BLOCK_MODE.Permutation);

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
            SpmBlockCipher.InitCodebook("b6a4c072764a2233db9c23b0bc79c143", SpmBlockCipher.BLOCK_MODE.Permutation);

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

    }
}