/**
 * @author Toni Schmidt
 *
 */

package org.toni.crypto.hashing;
import javax.xml.bind.DatatypeConverter;

public class Runner {

	public static void main(String[] args) {
		String testStr = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		byte [] input = testStr.getBytes();
		Sha256 instance = Sha256.getInstance();
		int a = 241;
		int b = 0;
		int c = 255;
		int res = instance.Maj(a,  b,  c);
		int res2 = instance.Ch(a,  b,  c);
		
		
        byte[] hash = instance.digest(input);
        
        
        
        System.out.println(DatatypeConverter.printHexBinary(hash));
	}

}
