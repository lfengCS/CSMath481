package edu.capital.eave.seminar_sp19;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * A simple RSA implementation without padding using BigIntegers.
 * For demonstration purposes & for generating public/private key for users
 * @author Ethan Ave <eave@capital.edu>
 */
public class RSA {

	// Demo
	public static void main(String[] args) {
		RSA test = new RSA(4096);
		BigInteger encryptedTest = test.encryptString("Hello world!", test.publicModulus());
		System.out.println("Encrypted test: " + encryptedTest);
		String decryptedTest = test.decryptString(encryptedTest);
		System.out.println("Decrypted test: " + decryptedTest);
	}


	/**
	 * Generates a random private and public key pair
	 *
	 * @param bits
	 */
	public RSA(int bits) {
		// Two random primes, generated as per the standard way with probablePrime using k/2 bits
		// Java's probablePrime uses both the Miller-Rabin and Lucas-Lehmer algorithms to
		// generate a sufficiently random prime. The probability that |p-q| is too small or that
		// two repeated primes are generated are so incredibly low that they will likely never happen
		// in practice.
		prime1 = BigInteger.probablePrime(bits / 2, random);
		prime2 = BigInteger.probablePrime(bits / 2, random);
		
		modulus = prime1.multiply(prime2);
		this.bits = bits;
		
		// Generate phi(n)
		BigInteger tot = prime1.subtract(BigInteger.ONE).multiply(prime2.subtract(BigInteger.ONE));
		privateExponent = PUBLIC_EXPONENT.modInverse(tot);
		
		System.out.println("Prime1: " + prime1);
		System.out.println("Prime2: " + prime2);
		System.out.println("PrivExp: " + privateExponent);
		System.out.println("Modulus: " + modulus);
	}
	
	public RSA() {
		
	}
	
	/**
	 * Always uses 65537 as the exponent as per the accepted standard!
	 * @param message
	 * @param publicModulus
	 * @return
	 */
	public BigInteger encryptString(String message, BigInteger publicModulus) {
		if(message.getBytes().length * 8 > bits) {
			throw new RuntimeException("String longer than " + bits + " bits!");
		}
		String asBytes = stringToHex(message);
		BigInteger hidden_m = new BigInteger(asBytes, 16);
		return hidden_m.modPow(PUBLIC_EXPONENT, publicModulus);
	}
	
	public String decryptString(BigInteger encryptedVal) {
		BigInteger recovered_m = encryptedVal.modPow(privateExponent, modulus);
		
		// Convert our decrypted integer to a string again
		String recovered_message = hexToString(recovered_m.toString(16));
		return recovered_message;
	}
	
    private static String hexToString(String hexStr) {
        StringBuilder output = new StringBuilder("");
         
        for (int i = 0; i < hexStr.length(); i += 2) {
            String str = hexStr.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
         
        return output.toString();
    }
    
    private static String stringToHex(String str) {
        char[] chars = str.toCharArray();
        StringBuilder hex = new StringBuilder();
        for (char ch : chars) {
            hex.append(Integer.toHexString((int) ch));
        }
     
        return hex.toString();
    }
	
    private int bits;
    
	// Our random instance used for generating our primes
	private final static SecureRandom random = new SecureRandom();
	
	// Public key information
	
	/**
	 * We use 65537 as our public exponent because it is large enough to
	 * still be fast, but provides some protection against vulnerability caused
	 * when e is too small AND improper padding is used. It should be noted that
	 * a small e does not in and of itself cause vulnerability, and would be the
	 * result of a poorly/improperly implemented padding algorithm.
	 */
	private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);
	private BigInteger modulus;
	
	
	// Private key information
	private BigInteger privateExponent;
	private BigInteger prime1;
	private BigInteger prime2;
	
	
	
	public BigInteger publicModulus() {
		return modulus;
	}
	public byte[] publicBytes() {
		return modulus.toByteArray();
	}
}
