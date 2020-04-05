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
	/* AES CTR SCA protection (masking and permutation) */
	/*
	 * [RB] NOTE: if you have memory "pressure" on your javacard, you can turn
	 * this off with a 'false' here at the expense of security of course ...
	 */
	static final boolean USE_AES_CTR_MASKING = true;
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
	/* Counter of encryptions for the same context */
	private short call_counter = 0;
	/* Local permutation to protect the CTR xoring */
	private byte[] ctr_permutation = null;
	private RandomData random = null;
	/* Local masks to mask CTR xoring */
	private byte[] ctr_masks = null;	

	/* Knuth shuffles to generate a random permutation */
	void gen_permutation(byte[] permutation, short size){
		if(USE_AES_CTR_MASKING == true){
			if(random == null){
				/* Initialize the secure random source */
				random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
			}
			if((permutation == null) || (tmp == null) || (permutation.length < size) || (size > 255)){
				CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
			}
			/* Go shuffle */
			short i;
			byte swp;
			for(i = 0; i < size; i++){
				permutation[i] = (byte) i;
			}
			if(size <= 2){
				return;
			}
			if(tmp.length < (short)(size - 2)){
				CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
			}
			random.generateData(tmp, (short) 0, (short) (size - 2));
			for(i = 0; i <= (short) (size - 2); i++){
				short j = (short) (size - i);
				j = (short) (((short)tmp[i] & 0xff) % j);
				j = (short)(i + j);
				swp = permutation[i];
				permutation[i] = permutation[j];
				permutation[j] = swp;
			}
		}
		return;
	}
	/* Generate random masks */
	void gen_masks(byte[] masks, short size){
		if(USE_AES_CTR_MASKING == true){
			if(random == null){
				/* Initialize the secure random source */
				random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
			}
			if((masks == null) || (masks.length < size) || (size > 255)){
				CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
			}
			random.generateData(masks, (short) 0, size);
		}
		return;
	}

	protected Aes(short key_len, byte asked_mode){
		iv = JCSystem.makeTransientByteArray(AES_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
		last_block = JCSystem.makeTransientByteArray(AES_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
		if(USE_AES_CTR_MASKING == true){
			tmp = JCSystem.makeTransientByteArray(AES_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
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
			/* If in CTR mode, we use a random 16 bytes to 16 bytes permutation for Xoring */
			if((asked_mode == CTR) && (USE_AES_CTR_MASKING == true)){
				ctr_permutation = JCSystem.makeTransientByteArray(AES_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);	
				ctr_masks = JCSystem.makeTransientByteArray(AES_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);	
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
			call_counter = 0;
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
					if(asked_iv.length < AES_BLOCK_SIZE){
						CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
					}
					Util.arrayCopyNonAtomic(asked_iv, (short) 0, iv, (short) 0, AES_BLOCK_SIZE);
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
								cipherAES.init(aesKey, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length);
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
								cipherAES.init(aesKey, Cipher.MODE_DECRYPT, iv, (short) 0, (short) iv.length);
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
		/* If input and output are the same and size is block aligned (which is always the case here since we do not handle padding),
		 * they should not overlap ... See the Javacard API documentation for Cipher.update */
		if(input == output){
			if((inputoffset < outputoffset) && (outputoffset < (short)(inputoffset + inputlen))){
				CryptoException.throwIt(CryptoException.ILLEGAL_USE);
			}
		}
		try{
			/* Increment our call counter */
			call_counter++;
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
					/* For CBC, since we have to use doFinal, we only tolerate a single call to the core AES primitive
					 * without calling init again (otherwise, this would yield in bad/unexpected results).
					 */
					if(call_counter >= 2){
						CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
					}
					/* !!NOTE: we would want to use the update method for CBC to keep the CBC context at the lower level,
					 * however the Cipher.update method is buffered and doFinal must be invoked otherwise bad results
					 * can be still buffered ... (see the Javacard API documentation)
					 */
					return cipherAES.doFinal(input, inputoffset, inputlen, output, outputoffset);
				case CTR:
					/* NOTE: this seems to be sub-optimal way of performing AES-CTR for big data chunks, since
					 * we call the hardware coprocessor for each block. An (a priori) improved way would be to
					 * call the hardware once for all the counters that we need by preparing them in
					 * in a working buffer ...
					 * However, the tests shows that we still perform better!
					 */
					short i, offset;
					if((short)(output.length - outputoffset) < inputlen){
						CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
					}
					/* Initialize offset to the last session ofset */
					offset = last_offset;
					if(USE_AES_CTR_MASKING == true){
						if(last_offset != 0){
							/* First block handling */
							/* Generate a random permutation */
							gen_permutation(ctr_permutation, (short)(AES_BLOCK_SIZE - last_offset));
							/* Generate random masks */
							gen_masks(ctr_masks, (short)(AES_BLOCK_SIZE - last_offset));
						}
					}
					short num_blocks = 0;
					for (i = 0; i < inputlen; i++){
						if(offset == 0){
							if(USE_AES_CTR_MASKING == true){
								short perm_size;
								num_blocks++;
								if(((short)(inputlen - i) < AES_BLOCK_SIZE) && (inputlen % AES_BLOCK_SIZE != 0)){
									/* Last block handling */
									perm_size = (short)(inputlen - i);
								}
								else{
									perm_size = AES_BLOCK_SIZE;
								}
								/* Generate a random permutation */
								gen_permutation(ctr_permutation, perm_size);
								/* Generate random masks */
								gen_masks(ctr_masks, perm_size);
							}
							cipherAES.doFinal(iv, (short) 0, (short) iv.length, last_block, (short) 0);
							/* Increment the counter */
							increment_iv();
						}
						if(USE_AES_CTR_MASKING == true){
							short i_perm, offset_perm;
							if((last_offset != 0) && (i < (short) (AES_BLOCK_SIZE - last_offset))){
                					        /* First block handling */
								i_perm = ctr_permutation[(short) (offset - last_offset)];
								offset_perm = (short)(i_perm + last_offset);
							}
							else{
								i_perm = offset_perm = ctr_permutation[offset];
							}
							if(num_blocks >= (short)1){
					                        /* Offset by the number of treated blocks */
								i_perm += (short) (AES_BLOCK_SIZE * (short) (num_blocks - 1));
							}
							if((last_offset != 0) && (i >= (short) (AES_BLOCK_SIZE - last_offset))){
					                        /* Block others than first block */
								i_perm += (short) (AES_BLOCK_SIZE - last_offset);
							}
							/* Sanity check */
							if((i_perm >= output.length) || ((short)(i_perm + inputoffset) >= input.length)){
								CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
							}
							/* XOR with masking and permutation to protect against SCA */
							output[i_perm] = (byte)(input[(short)(i_perm + inputoffset)] ^ ctr_masks[offset_perm]);
							output[i_perm] = (byte)(output[i_perm] ^ last_block[offset_perm]);
							output[i_perm] = (byte)(output[i_perm] ^ ctr_masks[offset_perm]);	
						}
						else{
							/* Straightforward XOR withtout any protection */
							output[i] = (byte)(input[(short)(i + inputoffset)] ^ last_block[offset]);
						}
						offset = (short) ((short)(offset + 1) % AES_BLOCK_SIZE);
					}
					last_offset = offset;
					return inputlen;
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
