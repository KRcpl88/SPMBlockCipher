using Microsoft.VisualStudio.TestTools.UnitTesting;
using SPM_PRNG = Spm.SimplePrng;

namespace Spm.Tests
{
    [TestClass()]
    public class SimplePrngTests
    {
        [TestMethod()]
        public void RandTest()
        {
            var prng = new SPM_PRNG();

            int i;

            prng.SetKeys(Util.HexToBin("b6a4c072764a2233db9c23b0bc79c143"));

            Assert.IsTrue(prng.Rand() == 0xa4b6);
            Assert.IsTrue(prng.Rand() == 0x72c0);
            Assert.IsTrue(prng.Rand() == 0x4a76);
            Assert.IsTrue(prng.Rand() == 0x3322);

            for (i = 0; 65536 > i; ++i)
            {
                prng.Rand();
            }
            Assert.IsTrue(prng.Rand() == 0x0191);
            Assert.IsTrue(prng.Rand() == 0x0a1b);
            Assert.IsTrue(prng.Rand() == 0xf03c);
            Assert.IsTrue(prng.Rand() == 0xd552);
        }
    }
}