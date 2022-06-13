using System;
using System.Diagnostics;

using SPM_WORD = System.UInt64;
using SPM_SBOX_WORD = System.UInt16;


namespace Spm
{
    public class SimplePrng
    {
        private SPM_WORD _state;
        private SPM_WORD _key;
        private int _idx;
        private byte[] _data;



        public SimplePrng()
        {
            _state = 0;
            _key = 0;
            _idx = 0;
        }

        public static void PrintCipherName()
        {
            Console.WriteLine("{0} bit simple PRNG ", sizeof(SPM_WORD) * 8);
        }

        public void SetKeys(byte[] keyData, int offest = 0)
        {
            Debug.Assert(keyData.Length >= (offest + GetKeyWidth()));

            _state = BitConverter.ToUInt64(keyData, offest);
            _key = BitConverter.ToUInt64(keyData, offest + sizeof(SPM_WORD));
            _key |= 1;  // make sure it is odd
            _idx = 0;
            _data = BitConverter.GetBytes(_state);
        }

        public SPM_SBOX_WORD Rand()
        {
            if (_idx >= (sizeof(SPM_WORD) / sizeof(SPM_SBOX_WORD)))
            {
                _idx = 0;
                _state += _key;
                _data = BitConverter.GetBytes(_state);
            }

            return (SPM_SBOX_WORD)(BitConverter.ToInt16(_data, (_idx++) << 1));
        }

        public static uint GetKeyWidth()
        {
            uint keyWidth;
            keyWidth = 2 * sizeof(SPM_WORD);
            return keyWidth;
        }
    }
}
