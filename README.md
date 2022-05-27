# SPMBlockCipher
A simple, high performance block cipher that scales easily to arbitrarily large key size and/or block size, based on a substitution (sbox), permutation, and xor bit mask

The way this block cipher works is simple:

1) Iterating over the entire block in overlapping 16 bit words, incrementing 8 bits at a time:
  a) apply a substitution using a 16 bit substitution array (sbox) which maps all 16 bit values onto another randomly selected 16 bit value
  b) Apply a 16 bit xor mask using a prng which increments for each 16 bit word after the substitution on the 16 bit output from the substitution step
  c) repeat over the entire block, incrementing 8 bits at a time so that each operation overlaps the previous operation by 8 bits
  d) when you get to the end of the block, reverse and repeat the same process going backwards until you get back to the beginning of the array
2) As a final step, apply a randomly selected permutation to each 8bit byte of the block, mapping each 8bit byte randomly to another position in the block.

The PRNG uses a 64 bit word state and key, and each time the PRNG is incremented, the key is added to the state, and then the new state is returned as the PRNG output.  The key is guaranteed to be odd (the least significant bit is always set to 1) so that the PRNG is guaranteed to produce a pseudo random sequence with a repeating period of 2^64, in other words it will enumerate all possible 64 bit words in pseudo random order before repeating.

Both the substitution and permutation arrays are initialized with a initial sequence of values, such that each value is unique and in the range 0-2^16 for the sbox and 0-block size for the permutation array.  The array is then shuffled by swapping each entry in the array with another randomly selected element of the ray using the preceding PRNG algorithm.  This is repeated 16 times for the entire array.

The resulting block cipher is simple, high performance, and secure.  It is simple enough it can easily be implemented in any given language, and is suitable for being used on low memory devices, on low performance CPU devices, or implemented as code inline in scripted environments.  The reference implementation uses a 128 byte blocksize, but the blocksize is arbitrarily large to defeat brute force attacks.  The PRNG mask continues to be incremented for each block, so every block in the input plaintext uses a unique mapping to the output ciphertext.  It is also recommended to use a nonce so the cipher sequence is unique for each nonce used, and obviously 
