import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/* This is a class dedicated to encrypted local storage.
 * The rationale is to provide a helper to transparently encrypt and decrypt sensitive data stored
 * locally in the token, using internal protected assets (protected using key bags).
 */
public class EncLocalStorage {
        private static final short AES_BLOCK_SIZE = 16;
        private AESKey aesKey = null;
	/* Cipher rinstance */
        private Cipher cipherAES = null;

        protected EncLocalStorage(){
		/* The following variables are *local* and locally allocated in the constructor:
		 * they are only used here and can be garbage collected afterwards ...
		 */
		/* Random */
        	RandomData random = null;
		byte[] tmp = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);;
                /* Initialize the secure random source */
                random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		/* Get a random Key */
		random.generateData(tmp, (short) 0, (short) 32);
		/* Allocate our local AES keybag */
                try {
                	aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, true);
                }
                catch(CryptoException e){
                       /* Our card might not support the 'true' flag for 'boolean keyEncryption': this however
                        * does not mean that the proprietary layer does not support it ... (see the Javacard spec).
                        * For instance JCOP cards throw an exception while the key is still encrypted ...
                        */
                 	aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
                }
		aesKey.setKey(tmp, (short) 0);
		/* Clear temporary buffer */
                Util.arrayFillNonAtomic(tmp, (short) 0, (short) tmp.length, (byte) 0);	
		/* Cipher instance */
                cipherAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
	}

	/* Transparently encrypt or decrypt local storage */
	private void Storage(byte[] input, short inputoffset, short inputlen, byte[] output, short outputoffset, byte theMode){
		if(inputlen % AES_BLOCK_SIZE != 0){
			CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		}
                if(input == output){
                        if((inputoffset < outputoffset) && (outputoffset < (short)(inputoffset + inputlen))){
                                CryptoException.throwIt(CryptoException.ILLEGAL_USE);
                        }
                }
                if(cipherAES == null){
 			CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
		}
		cipherAES.init(aesKey, theMode);
		short outlen = cipherAES.doFinal(input, inputoffset, inputlen, output, outputoffset);
		if(outlen != inputlen){
			CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		}
	}
	
	/* Transparently encrypt local storage */
	public void Encrypt(byte[] input, short inputoffset, short inputlen, byte[] output, short outputoffset){
		Storage(input, inputoffset, inputlen, output, outputoffset, Cipher.MODE_ENCRYPT);
	}

	/* Transparently decrypt local storage */
	public void Decrypt(byte[] input, short inputoffset, short inputlen, byte[] output, short outputoffset){
		Storage(input, inputoffset, inputlen, output, outputoffset, Cipher.MODE_DECRYPT);
	}
	
	/* Clean stuff */
	public void destroy(){
		aesKey.clearKey();
	}
}
