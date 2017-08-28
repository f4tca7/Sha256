/**
 * @author Toni Schmidt
 * SHA-256 implementation as per the NIST spec: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 * All section references in below comments refer to the NIST spec
 */

package org.toni.crypto.hashing;

import java.nio.ByteBuffer;

public class Sha256 {
	
// Section 5.5.3
	private static final int[] H = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	
// Section 4.2.2
	private static final int[] K = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		                             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		                             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		                             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		                             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		                             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		                             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		                             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
// Re-used int array
	private static int [] words = new int[64];
   
	private Sha256() {		
	}
	

	public static Sha256 getInstance() {
		return new Sha256();
	}	

	/** 
	 * Ch (for "Choose"). If bit n in x == 1: bit n in result is the same as bit n of input y. else, take bit n of input z
	 *  
	 * x: 1111 0000
	 * y: 0000 0000
	 * z: 1111 1111
	 * ------------
	 * -> 0000 1111
	 * 
	 *   x & y:
	 *   1111 0000
	 * & 0000 0000
	 * = 0000 0000
	 * 
	 * 	 ~x & z
	 *   0000 1111
	 * & 1111 1111
	 * = 0000 1111
	 * 
	 *   (x & y) ^ (~x & z )
	 *   0000 0000
	 * ^ 0000 1111
	 * = 0000 1111
	 *      
	 * @return 
	 */
	private int Ch(int x, int y, int z) {
		return (x & y) ^ (~x & z);		 
	}
	
	
	/**
	 * Maj (for "Majority"). If min. 2 of 3 bits at position n in inputs x, y, z are 1: Bit n in result is 1. Otherwise 0.
	 * 
	 * x: 1101 1101
	 * y: 1011 0011
	 * z: 1101 0011
	 * ------------ 
	 * -> 1101 0011
	 *  
	 *   x & y:
	 *   1101 1101
	 * & 1011 0011
	 * = 1001 0001 
	 *  
	 *   x & z:
	 *   1101 1101
	 * & 1101 0011 
	 * = 1101 0001
	 * 
	 *   y & z:
	 *   1011 0011
	 * & 1101 0011 
	 * = 1001 0011   
	 * 
	 *   (x & y) ^ (x & z ) ^ (y & z )
	 *   1001 0001
	 * ^ 1101 0001
	 * ^ 1001 0011
	 * = 1101 0011 
	 */	
	private int Maj(int x, int y, int z) {
		return (x & y) ^ (x & z ) ^ (y & z );
	}	

	/**
	 * Rotate Right, meaning a right shift where the overflow to the right is added to the left
	 * Sample for ROTR(2, 124)
	 * n: 2
	 * x: 		0000 0000 0000 0000 0000 0000 ‭0111 1101‬
	 * 
	 *   x >>> n ...  Operator ">>>" in Java is an unsigned right shift... so the value will always be filled with zeros from the left      ‬
	 * x >> 2:  0000 0000 0000 0000 0000 0000‭ ‭0001 1111 
	 * 
	 *   (x << (32-n)
	 * x << 30: 0100 0000 0000 0000 0000 0000 0000 0000
	 * 
	 * 	 (x >>> n) | (x << (32-n))
	 * 			0100 0000 0000 0000 0000 0000 0001 1111
	 */
    private int ROTR(int n, int x) {
        return (x >>> n) | (x << (32-n));
    }	
	
    private int Sum0(int x) {
    	int a = ROTR(2, x);
    	int b = ROTR(13, x);
    	int c = ROTR(22, x);
    	int ret = a ^ b ^ c;
		return ret;
    }
    
    private int Sum1(int x) {
    	int a = ROTR(6, x);
    	int b = ROTR(11, x);
    	int c = ROTR(25, x);
    	int ret = a ^ b ^ c;
		return ret;
    }  
    
    private int Sigma0(int x) {
    	int a = ROTR(7, x);
    	int b = ROTR(18, x);
    	int c = x >>> 3;        
    	int ret = a ^ b ^ c;
		return ret;
    }       
    
    private int Sigma1(int x) {
    	int a = ROTR(17, x);
    	int b = ROTR(19, x);
    	int c = x >>> 10;        
    	int ret = a ^ b ^ c;
		return ret;
    }   
    
    
    private byte[] intToBytes(int i) {
    	return ByteBuffer.allocate(4).putInt(i).array();
    }    
    
    private int bytesToInt(byte b3, byte b2, byte b1, byte b0) {
        return (((b3       ) << 24) |
                ((b2 & 0xff) << 16) |
                ((b1 & 0xff) <<  8) |
                ((b0 & 0xff)      ));
    }    

    /**
     * Main digest method
     * @param msg The message input
     * @return The hash digest
     */
    public byte [] digest(byte[] msg) {
    	// 1. Pad message
    	byte[] paddedMsg = padMsg(msg);
    	// 2. Parse message
    	byte[][] parsedMsg = parseMsg(paddedMsg);
    	// 3. Hash computation
    	byte[] messageDigest = digestMsg(parsedMsg);
    	return messageDigest;
    }
    

    /**
     * Computes the hash digest as per section 6.2.2
     * 1) Initialize the message schedule, consisting of 64 words (each 32 bit)
     * 2) Initialize working variables a ... h with the hash values of the previous iteration
     * 3) Compute the working variable for the current iteration
     * 4) Update the hash value of the current iteration
     * @param parsedMsg The parsed message, consisting of 512-bit blocks
     * @return The hash digest
     */
    private byte[] digestMsg(byte[][] parsedMsg) {
    	
    	int a, b, c, d, e, f, g, h;
    	int[] hashValues = new int[8];
    	
    	// Initialize hash values for the first iteration, as per section 5.3.3
    	System.arraycopy(H, 0, hashValues, 0, 8);
    	
    	// Iterate through the input message blocks
    	for (int i = 0; i < parsedMsg.length; i++) {
    		// 1. Prepare message schedule
    		fillWords(parsedMsg[i]);
    		
    		// 2. Initialize working variables with hash values of previous iteration
    		a = hashValues[0];
    		b = hashValues[1];
    		c = hashValues[2];
    		d = hashValues[3];
    		e = hashValues[4];
    		f = hashValues[5];
    		g = hashValues[6];
    		h = hashValues[7];
    		
    		// 3. Compute updated working variables
    		for (int t = 0; t < 64; t++) {
    			int T1 = h + Sum1(e) + Ch(e, f, g) + K[t] + words[t];
    			int T2 = Sum0(a) + Maj(a, b, c);
    			h = g;
    			g = f;
    			f = e;
    			e = d + T1;
    			d = c;
    			c = b;
    			b = a;
    			a = T1 + T2;    				
    		}
    		
    		// 4. Update hash values
    		hashValues[0] = a + hashValues[0];
    		hashValues[1] = b + hashValues[1];
    		hashValues[2] = c + hashValues[2];
    		hashValues[3] = d + hashValues[3];
    		hashValues[4] = e + hashValues[4];
    		hashValues[5] = f + hashValues[5];
    		hashValues[6] = g + hashValues[6];
    		hashValues[7] = h + hashValues[7];
    	}    	
    	
        byte[] digest = new byte[32]; 
        // Concatenate the hash values to one 256-bit output byte[]
        for (int i = 0; i < 8; i++) {
            System.arraycopy(intToBytes(hashValues[i]), 0, digest, 4 * i, 4);
        }    	
    	
    	return digest;
    }
    
	/**
	 * Prepares the message schedule as per section 6.2.2
	 * @param block One 512-bit input block
	 */
    private void fillWords(byte[] block) {   
		for(int t = 0; t < 64; t++) {
	    	if (t < 16) {		// for 0 <= t <= 15 	
				int wordStartIndex = t * 4;	// wordIndex * 4 since each word occupies four byte
				byte b3 = block[wordStartIndex];
				byte b2 = block[wordStartIndex + 1];
				byte b1 = block[wordStartIndex + 2];
				byte b0 = block[wordStartIndex + 3];
				int word = bytesToInt(b3, b2, b1, b0);	// convert byte[] to int
				words[t] = word; 				// remember for future usage
			} else {					// for 16 <= t <= 63 ... lots of bitwise mixing			
				int f1 = Sigma1(words[t - 2]);
				int f2 = words[t - 7];
				int f3 = Sigma0(words[t - 15]);
				int f4 = words[t - 16];
				words[t] = f1 + f2 + f3 + f4;			
			}
		}
    }
    
    /**
     * As per section 5.2.1
     * Parses the padded:
     * The message is split into blocks of 512-bit/64-byte length.
     * Each of those blocks will serve as input for one iteration in the hash computation
     * @param paddedMsg the padded input message
     * @return A two-dimensional array byte[block][message]
     */
    private byte [][] parseMsg(byte[] paddedMsg) {
    	int paddedMsgLen = paddedMsg.length;
    	int numBlocks = paddedMsgLen / 64;
    	byte [][] blocks = new byte [numBlocks][64];  // each block contains sixteen 32-bit words == 64 byte
    	
    	// fill message blocks
    	for (int i = 0; i < paddedMsgLen / 64; i++) {
			System.arraycopy(paddedMsg, i * 64, blocks[i], 0, 64);
    	}   	
    	return blocks;
    }
    
    /**
     * As per section 5.1.1
     * Adds a padding to the input message, so that:
     * 1) The overall message length in bits is divisible by 512 (because it will be separated into 512-bit blocks in the next stage)
     * 2) The bit immediately after the message is 1
     * 3) The bits following are 0
     * 4) The last 64 bits are the input message length
     * @param msg The input message
     * @return Padded message
     */
    private byte[] padMsg(byte[] msg) {
    	int messageLength = msg.length;
    	int overflow = messageLength % 64; // overflow bytes are not in a 64-byte/512-bit block 
    	int paddingLength;
    	
    	if(64 - overflow >= 9) { // we need min. 72 bit (9 * 8 bit) space: 1 byte for the "1"-bit directly after the message, 8 byte for message length  
    		paddingLength = 64 - overflow;
    	} else {	// if we have less than 72 bit of space between the message and the next full 512-bit block, add another 512-bit block
    		paddingLength = 128 - overflow;
    	}
    	
    	byte [] padding = new byte [paddingLength];
    	
    	padding[0] = (byte) 0x80; // byte with leading 1-bit (1000 0000)
    	
    	long lenInBit = messageLength * 8; // message length as number of bits. This needs to be filled into the trailing 64 bit of the last block
    	
    	// bitwise copy of length-integer into padding[] byte array
    	// 8 iterations, one byte per iteration, to fill 64 bit
        for (int i = 0; i < 8; i++) {
        	// shift right i byte
        	long shiftRight = lenInBit >>> (8 * i);
        	// truncate the rightmost byte
        	byte b = (byte) (shiftRight  & 0xFF);
        	// highest index in the array gets the lowest value bit
        	padding[padding.length - 1 - i] = b;
        }    	
    	
        // construct output array including padding, with length (in bit) divisible by 512
    	byte [] paddedMsg = new byte [messageLength + paddingLength];
    	// copy original message
        System.arraycopy(msg, 0, paddedMsg, 0, messageLength);
        // copy padding
        System.arraycopy(padding, 0, paddedMsg, messageLength, padding.length);   	
        
        return paddedMsg;
    }
    
    
    
    
}
