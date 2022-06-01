using Microsoft.VisualStudio.TestTools.UnitTesting;
using Spm;
using System;
using System.Collections.Generic;
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

    }
}