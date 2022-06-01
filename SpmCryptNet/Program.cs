using System;

namespace Spm
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 5)
            {
                throw new ArgumentException("usage: E|EP|D|DP filein fileout key|password codebook");
            }

            byte[] key;

            try
            {
                key = Util.HexToBin(args[3]);
            }
            catch (FormatException)
            {
                key = Util.ParsePassword(args[3], SpmBlockCipher.GetKeyWidth());
            }

            switch (args[0])
            {
                case "E":
                    SpmBlockCipher.InitCodebook(args[4], SpmBlockCipher.BLOCK_MODE.NoPermutation);
                    Util.FbcEncryptFile(args[1], args[2], key);
                    break;
                case "EP":
                    SpmBlockCipher.InitCodebook(args[4], SpmBlockCipher.BLOCK_MODE.Permutation);
                    Util.FbcEncryptFile(args[1], args[2], key);
                    break;
                case "D":
                    SpmBlockCipher.InitCodebook(args[4], SpmBlockCipher.BLOCK_MODE.NoPermutation);
                    Util.FbcDecryptFile(args[1], args[2], key);
                    break;
                case "DP":
                    SpmBlockCipher.InitCodebook(args[4], SpmBlockCipher.BLOCK_MODE.Permutation);
                    Util.FbcDecryptFile(args[1], args[2], key);
                    break;
                default:
                    throw new ArgumentException("usage: E|EP|D|DP filein fileout key|password codebook");
            }
        }
    }
}
