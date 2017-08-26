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
		
		
		
        byte[] hash = Sha256.getInstance().digest(input);
        System.out.println(DatatypeConverter.printHexBinary(hash));
	}

}
