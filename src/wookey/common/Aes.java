import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class Aes {
	/* Available modes */
	static final byte ECB = 0;
	static final byte CBC = 1;
	static final byte CTR = 2;
	static final byte ENCRYPT = 0;
	static final byte DECRYPT = 1;
	static final short AES_BLOCK_SIZE = 16;
	/* Two variants of the CTR implementation (see below) */
	private final byte AES_CTR_IMPLEMENTATION = 0;
	/* Current AES mode (ECB, CBC, CTR) */
	private byte mode;
	/* Direction */
	private byte dir;
	/* Current direction (encrypt or decrypt) */
	/* Saved context (for CTR) */
	private byte[] iv = null;
	private short last_offset = 0;
	private byte[] last_block = null;
	/* Our instance */
	private Cipher cipherAES = null;
	private AESKey aesKey = null;
	/* Tmp buffer */
	private byte[] tmp = null;

	protected Aes(short key_len, byte asked_mode){
		iv = JCSystem.makeTransientByteArray(AES_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
		last_block = JCSystem.makeTransientByteArray(AES_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
		if(AES_CTR_IMPLEMENTATION == (byte) 1){
			tmp = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_DESELECT);
		}
		try{
			switch(asked_mode){
				case ECB:
				case CBC:
				case CTR:
					mode = asked_mode;
					break;
				default:
					CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
			}
			/* Initialize our AES context */
			short key_builder = 0;
			byte cipher_instance = 0;
			switch(key_len){
				case 16:
					key_builder = KeyBuilder.LENGTH_AES_128;
					break;
				case 24:
					key_builder = KeyBuilder.LENGTH_AES_192;
					break;
				case 32:
					key_builder = KeyBuilder.LENGTH_AES_256;
					break;
				default:
					CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
			}
			switch(asked_mode){
				case ECB:
				case CTR:
					cipher_instance = Cipher.ALG_AES_BLOCK_128_ECB_NOPAD;
					break;
				case CBC:
					cipher_instance = Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;
					break;
				default:
					CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
			}
			try {
				aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, key_builder, true);
			}
			catch(CryptoException e){
				/* Our card might not support the 'true' flag for 'boolean keyEncryption': this however
				 * does not mean that the proprietary layer does not support it ... (see the Javacard spec).
				 * For instance JCOP cards throw an exception while the key is still encrypted ...
				 */
				aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, key_builder, false);
			}
			cipherAES = Cipher.getInstance(cipher_instance, false);
		}
                catch(CryptoException exception)
                {
                    switch(exception.getReason()){
                        case CryptoException.ILLEGAL_USE:
                                ISOException.throwIt((short) 0xAAD0);
                                break;
                        case CryptoException.ILLEGAL_VALUE:
                                ISOException.throwIt((short) 0xAAD1);
                                break;
                        case CryptoException.INVALID_INIT:
                                ISOException.throwIt((short) 0xAAD2);
                                break;
                        case CryptoException.NO_SUCH_ALGORITHM:
                                ISOException.throwIt((short) 0xAAD3);
                                break;
                        case CryptoException.UNINITIALIZED_KEY:
                                ISOException.throwIt((short) 0xAAD4);
                                break;
                        default:
                                ISOException.throwIt((short) 0xAAD5);
                                break;
                        }
                }

	}

	public void aes_init(byte[] key, byte[] asked_iv, byte asked_dir){
		try{
			last_offset = 0;
			switch(mode){
				case ECB:
					if(asked_iv != null){
						CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
					}
					break;
				case CBC:
				case CTR:
					if(asked_iv == null){
						CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
					}
					if(asked_iv.length != AES_BLOCK_SIZE){
						CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
					}
					Util.arrayCopyNonAtomic(asked_iv, (short) 0, iv, (short) 0, (short) asked_iv.length);
					break;
				default:
					CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
			}
			switch(asked_dir){
				case ENCRYPT:
				case DECRYPT:
					dir = asked_dir;
					break;
				default:
					CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
			}
                        aesKey.setKey(key, (short) 0);
			switch(asked_dir){
				case ENCRYPT:
					if(asked_iv == null){
						cipherAES.init(aesKey, Cipher.MODE_ENCRYPT);
					}
					else{
						switch(mode){
							case CBC:
								cipherAES.init(aesKey, Cipher.MODE_ENCRYPT, asked_iv, (short) 0, (short) asked_iv.length);
								break;
							case CTR:
								cipherAES.init(aesKey, Cipher.MODE_ENCRYPT);
								break;
							default:
								CryptoException.throwIt(CryptoException.ILLEGAL_USE);
						}
					}
					break;
				case DECRYPT:
					if(asked_iv == null){
						cipherAES.init(aesKey, Cipher.MODE_DECRYPT);
					}
					else{
						switch(mode){
							case CBC:
								cipherAES.init(aesKey, Cipher.MODE_DECRYPT, asked_iv, (short) 0, (short) asked_iv.length);
								break;
							case CTR:
								cipherAES.init(aesKey, Cipher.MODE_ENCRYPT);
								break;
							default:
								CryptoException.throwIt(CryptoException.ILLEGAL_USE);
						}
					}
					break;
			}
		}
                catch(CryptoException exception)
                {
                    switch(exception.getReason()){
                        case CryptoException.ILLEGAL_USE:
                                ISOException.throwIt((short) 0xAAD0);
                                break;
                        case CryptoException.ILLEGAL_VALUE:
                                ISOException.throwIt((short) 0xAAD1);
                                break;
                        case CryptoException.INVALID_INIT:
                                ISOException.throwIt((short) 0xAAD2);
                                break;
                        case CryptoException.NO_SUCH_ALGORITHM:
                                ISOException.throwIt((short) 0xAAD3);
                                break;
                        case CryptoException.UNINITIALIZED_KEY:
                                ISOException.throwIt((short) 0xAAD4);
                                break;
                        default:
                                ISOException.throwIt((short) 0xAAD5);
                                break;
                        }
                }
	}

        private void increment_iv(){
                short i;
                byte end = 0, dummy = 0;
                for(i = (short)iv.length; i > 0; i--){
                        if(end == 0){
                                if((++iv[(short)(i - 1)] != 0)){
                                        end = 1;
                                }
                        }
                        else{
                                dummy++;
                        }
                }
        }

	public short aes(byte[] input, short inputoffset, short inputlen, byte[] output, short outputoffset){
		try{
			if(cipherAES == null){
				CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
			}
			switch(mode){
				case ECB:
					if(inputlen % AES_BLOCK_SIZE != 0){
						CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
					}
					return cipherAES.doFinal(input, inputoffset, inputlen, output, outputoffset);
				case CBC:
					if(inputlen % AES_BLOCK_SIZE != 0){
						CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
					}
					/* Note: we use the update method for CBC to keep this feature at the lower level */
					return cipherAES.update(input, inputoffset, inputlen, output, outputoffset);
				case CTR:
					if(AES_CTR_IMPLEMENTATION == (byte) 0){
						/* NOTE: this seems to be sub-optimal way of performing AES-CTR for big data chunks, since
						 * we call the hardware coprocessor for each block. An improved way would be to
						 * call the hardware once for all the counters that we need by preparing them in
						 * in a working buffer ...
						 * However, the tests (see the code below) shows that we still perform better
						 */
						short i;
						short offset;
						if((short)(output.length - outputoffset) < inputlen){
							CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
						}
						offset = last_offset;
						for (i = 0; i < inputlen; i++){
							if(offset == 0){
								cipherAES.doFinal(iv, (short) 0, (short) iv.length, last_block, (short) 0);
								// Increment the counter
								increment_iv();
							}
							output[i] = (byte)(input[(short)(i + inputoffset)] ^ last_block[offset]);
							offset = (short) ((short)(offset + 1) % AES_BLOCK_SIZE);
						}
						last_offset = offset;
						return inputlen;
					}
					else{
						short i, bytes, hardware_bytes_to_encrypt;
						byte state = 0;
						bytes = 0;
						if(last_offset != 0){
							for(i = last_offset; i < AES_BLOCK_SIZE; i++){
								output[(short)(outputoffset + i)] = (byte)(input[(short)(inputoffset + i)] ^ last_block[i]);
								bytes++;
								last_offset++;
								if(bytes > inputlen){
									return inputlen;
								}
							}
						}
						if((short)(inputlen - bytes) < AES_BLOCK_SIZE){
							hardware_bytes_to_encrypt = 0;
							state = 1;
						}
						if((short)(inputlen - bytes) % AES_BLOCK_SIZE != 0){
							hardware_bytes_to_encrypt = (short)((inputlen - bytes) - ((short)(inputlen - bytes) % AES_BLOCK_SIZE));
							state = 1;
						}
						else{
							hardware_bytes_to_encrypt = (short)(inputlen - bytes);
							state = 1;
						}
						if(hardware_bytes_to_encrypt != 0){
							for(i = 0; i < (short)(hardware_bytes_to_encrypt / AES_BLOCK_SIZE); i++){
								Util.arrayCopyNonAtomic(iv, (short) 0, tmp, (short) (i * AES_BLOCK_SIZE), AES_BLOCK_SIZE);
								increment_iv();
							}
							cipherAES.doFinal(tmp, (short) 0, hardware_bytes_to_encrypt, tmp, (short) 0);
							for(i = 0; i < hardware_bytes_to_encrypt; i++){
								output[(short)(outputoffset + i)] = (byte)(input[(short)(inputoffset + i)] ^ tmp[i]);
							}
						}
						if((short)(inputlen - bytes - hardware_bytes_to_encrypt) == 0){
							last_offset = 0;
							return inputlen;
						}
						if(state == (short)1){
							// Encrypt our last block 
							cipherAES.doFinal(iv, (short) 0, AES_BLOCK_SIZE, last_block, (short) 0);
							for(i = 0; i < (short) (inputlen - bytes - hardware_bytes_to_encrypt); i++){
								output[(short) (outputoffset + bytes + hardware_bytes_to_encrypt + i)] = (byte) (input[(short) (inputoffset + bytes + hardware_bytes_to_encrypt + i)] ^ last_block[i]);
								last_offset++;
							}
							increment_iv();
						}
						return inputlen;
					}
				default:
					CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
			}
		}
                catch(CryptoException exception)
                {
                    switch(exception.getReason()){
                        case CryptoException.ILLEGAL_USE:
                                ISOException.throwIt((short) 0xAAD0);
                                break;
                        case CryptoException.ILLEGAL_VALUE:
                                ISOException.throwIt((short) 0xAAD1);
                                break;
                        case CryptoException.INVALID_INIT:
                                ISOException.throwIt((short) 0xAAD2);
                                break;
                        case CryptoException.NO_SUCH_ALGORITHM:
                                ISOException.throwIt((short) 0xAAD3);
                                break;
                        case CryptoException.UNINITIALIZED_KEY:
                                ISOException.throwIt((short) 0xAAD4);
                                break;
                        default:
                                ISOException.throwIt((short) 0xAAD5);
                                break;
                        }
                }
		return 0;
	}
}
