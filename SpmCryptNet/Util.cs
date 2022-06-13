using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;


using FBC_PRNG = Spm.SimplePrng;
using FBC_WORD = System.UInt64;
using FBC_SBOX_WORD = System.UInt16;
using size_t = System.UInt32;

namespace Spm
{
    public class Util
    {
        public enum EFileCryptProcess
        {
            Encrypt,
            Decrypt
        };


        public static byte [] ParsePassword(string password, uint cb)
        {
            uint i = 0;
            uint j = 0;
            bool firstPass = true;
            bool passwordIncomplete = true;
            byte[] temp = null;
            byte[] bin = new byte[cb];

            while (firstPass || passwordIncomplete)
            {
                if (temp == null)
                {
                    temp = Encoding.UTF8.GetBytes(password);
                    j = 0;
                }

                bin[i] += temp[j];
                ++j;

                if (j >= password.Length)
                {
                    passwordIncomplete = false;
                    j = 0;
                }

                ++i;
                if (i >= cb)
                {
                    firstPass = false;
                    i = 0;
                }
            }
#if (DEBUG)
            Console.Write("Pwd data: ");
            foreach (byte c in bin)
            {
                Console.Write("{0:X2}", c);
            }
            Console.WriteLine();
#endif
            return bin;
        }

        public static byte[] HexToBin(string hex)
        {
            if(hex.Length == 0)
            {
                return null;
            }

            byte[] bin = new byte[((hex.Length-1)/2) +1];
            int i;
            int chunkLength;

            for (i = 0; i < bin.Length; ++i)
            {
                // for the last chunk, it may be 1 or 2 chars in length
                chunkLength = ((i < (bin.Length - 1)) ? 2 : (((hex.Length + 1) % 2) + 1));

                Debug.Assert(((i * 2) + chunkLength) <= hex.Length);

                // start from the end and work backwards
                bin[bin.Length - i -1] = (byte)(Convert.ToInt32(hex.Substring((hex.Length - (i * 2 + chunkLength)), chunkLength), 16));
            }
            return bin;
        }

        public static void PrintBin(byte[] bin)
        {
            foreach(byte c in bin)
            {
                Console.Write("{0:X2}", c);
            }
        }

        public static void ApplyNonce(byte[] nonce, byte[] key, SpmBlockCipher cryptor)
        {
            var oneWayHash =  new SpmBlockCipher();
            var encryptedNonce = new byte[SpmBlockCipher.GetKeyWidth()];
            var block = new byte[SpmBlockCipher.BlockSizeBytes];

            Debug.Assert(nonce.Length <= SpmBlockCipher.GetKeyWidth());
            Debug.Assert(key.Length == SpmBlockCipher.GetKeyWidth());

#if DEBUG
            Console.Write("Raw Nonce: ");
            PrintBin(nonce);
            Console.WriteLine();
#endif
            nonce.CopyTo(block, 0);

            oneWayHash.SetKeys(key);

            oneWayHash.Encrypt(block);

            block.AsSpan(0, nonce.Length).CopyTo(encryptedNonce);

#if DEBUG
            Console.Write("Encrypted Nonce: ");
            PrintBin(encryptedNonce);
            Console.WriteLine();
#endif

            Debug.Assert(key.Length <= encryptedNonce.Length);
            cryptor.SetKeys(encryptedNonce);
        }

        public const string PasswordMap = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789)!@#$%^&*(+-=[]{};:.,<>";

        public static byte[] MakeKey(
            size_t cb
            )
        {
            var random = new byte[cb];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);
            }

            return random;
        }

        public static byte[] GenNonceFromInput()
        {
            var nonce = new byte[SpmBlockCipher.GetKeyWidth()];

            var timer = new Stopwatch();
            int i = sizeof(long);
            timer.Start();
            BitConverter.GetBytes(Environment.TickCount).CopyTo(nonce, i);
            i += sizeof(int);
            BitConverter.GetBytes(Process.GetCurrentProcess().Id).CopyTo(nonce, i);
            i += sizeof(int);
            BitConverter.GetBytes(Thread.CurrentThread.ManagedThreadId).CopyTo(nonce, i);
            i += sizeof(int);
            BitConverter.GetBytes(DateTime.Now.Ticks).CopyTo(nonce, i);
            Console.WriteLine("Press enter to collect entropy...");
            Console.Read();
            timer.Stop();

            BitConverter.GetBytes(timer.ElapsedTicks).CopyTo(nonce, 0);
            PrintBin(nonce);
            Console.WriteLine("");

            return nonce;
        }


        public static void FbcEncryptFile(string plaintext, string ciphertext, byte[] key)
        {
            var cryptor = new SpmBlockCipher();
            byte[] nonce;
            UInt64 fileSize;

            SpmBlockCipher.PrintCipherName();

            using (FileStream fileIn = File.OpenRead(plaintext))
            {
                nonce = MakeKey(SpmBlockCipher.GetKeyWidth());

                fileSize = (UInt64)fileIn.Length;
                using (FileStream fileOut = File.OpenWrite(ciphertext))
                {
                    fileOut.Write(nonce);
                    fileOut.Write(BitConverter.GetBytes(fileSize));

                    ApplyNonce(nonce, key, cryptor);

                    FbcProcessFile(fileIn, fileOut, fileSize, cryptor, EFileCryptProcess.Encrypt);
                }
            }
        }

        public static void FbcDecryptFile(string ciphertext, string plaintext, byte[] key)
        {
            var cryptor = new SpmBlockCipher();
            var nonce = new byte[SpmBlockCipher.GetKeyWidth()];
            var fileSize = new byte[sizeof(UInt64)];
            int bytesRead = 0;

            SpmBlockCipher.PrintCipherName();

            using (FileStream fileIn = File.OpenRead(ciphertext))
            {
                bytesRead = fileIn.Read(nonce);
                if (bytesRead != nonce.Length)
                {
                    throw (new Exception("Corrupt or invalid encrypted file"));
                }
                bytesRead = fileIn.Read(fileSize);
                if (bytesRead != fileSize.Length)
                {
                    throw (new Exception("Corrupt or invalid encrypted file"));
                }

                using (FileStream fileOut = File.OpenWrite(plaintext))
                {
                    ApplyNonce(nonce, key, cryptor);

                    FbcProcessFile(fileIn, fileOut, BitConverter.ToUInt64(fileSize), cryptor, EFileCryptProcess.Decrypt);
                }
            }
        }


        static void FbcProcessFile(FileStream fileIn, FileStream fileOut, UInt64 fileSize, SpmBlockCipher cryptor, EFileCryptProcess fileCryptProcess)
        {
            var buf = new byte[SpmBlockCipher.BlockSizeBytes];
            int bytesRead;
            UInt64 totalBytes = 0;
            var timer = new Stopwatch();

            timer.Start();

            do
            {
                bytesRead = fileIn.Read(buf);

                if (0 < bytesRead) 
                {

                    switch (fileCryptProcess)
                    {
                        case EFileCryptProcess.Encrypt:
                            cryptor.Encrypt(buf);
                            break;
                        case EFileCryptProcess.Decrypt:
                            if (bytesRead != SpmBlockCipher.BlockSizeBytes)
                            {
                                throw (new Exception("Corrupt or invalid encrypted file"));
                            }
                            cryptor.Decrypt(buf);
                            break;
                    }

                    totalBytes += (UInt64)bytesRead;

                    if (totalBytes < fileSize)
                    {
                        fileOut.Write(buf);
                    }
                    else 
                    {
                        fileOut.Write( buf, 0, (int)(SpmBlockCipher.BlockSizeBytes - (totalBytes - fileSize)) );
                    }
                }
            }
            while (bytesRead == buf.Length);

            timer.Stop();

            Console.WriteLine("De/Encrypted {0} Kbytes in {1} ms", totalBytes >> 10,
                timer.ElapsedMilliseconds);

            if (timer.ElapsedMilliseconds > 0)
            {
                Console.WriteLine("  {0} Mbits per second",
                    ((totalBytes * 1000) >> 17) / (UInt64)(timer.ElapsedMilliseconds)
                    );
            }
        }
    }
}


