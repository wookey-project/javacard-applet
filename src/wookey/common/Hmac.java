import javacard.framework.*;
import javacard.security.*;

/*
 * This implementation of HMAC is a wrapper that either uses a native implementation
 * (ALG_HMAC_SHA_256 and so on), or fall back to a pure software implementation.
 * The software implementation optionally uses masking to try limiting some leaks.
 */
public class Hmac {
	/* !!WARNING: using native HMAC can provoke unexpected errors on
	 * cards that do not retur an error when getting an instance, but
	 * raise an exception when using the instance ... Turn to 'false'
	 * to fall back to software HMAC if this happens.
	 */
	private static final boolean TRY_USE_NATIVE_HMAC = true;
	/* If we have native HMAC support, use it */
	private boolean use_native_hmac = false;
	Signature hmac_instance = null;
	HMACKey hmac_key = null;
	/* The message digest instances */
	private MessageDigest md_i = null;
	private MessageDigest md_o = null;
	private MessageDigest local_md = null;
	private byte[] ipad = null;
	private byte[] opad = null;
	private byte[] local_key;
	private byte[] dgst_i;
	private byte digest = 0;
	/* For random masking */
	/* !!WARNING: the ipad/opad masking can be hard on the eeprom initialization, and some
	 * Javacards won't be compatible with this. Turn to false if you have an error at
	 * first applet selection when eeprom is initialized by the applet ...
	 * (masking has been tested to be working on NXP J3D081 smart cards)
	 */
	private static final boolean USE_HMAC_MASKING = true;
        private RandomData random = null;
	private byte[] orig_ipad_masks = null;
	private byte[] orig_opad_masks = null;
	private byte[] ipad_masks = null;
	private byte[] opad_masks = null;

	protected Hmac(byte digest_type){
		if(TRY_USE_NATIVE_HMAC == true){
			/* Check native HMAC support on the card
			 * NOTE: HMAC implementation is unfortunately not present on the tested cards so far ...
			 * but we prepare its usage on compatible cards!
			 */
			use_native_hmac = true;
			try {
				switch(digest_type){
					case MessageDigest.ALG_SHA_224:
						CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
						break;
					case MessageDigest.ALG_SHA_256:
						try {
							hmac_key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, true);
						}
						catch(CryptoException e){
							hmac_key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
						}
						hmac_instance = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
						break;
					case MessageDigest.ALG_SHA_384:
						try {
							hmac_key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_HMAC_SHA_384_BLOCK_128, true);
						}
						catch(CryptoException e){
							hmac_key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_HMAC_SHA_384_BLOCK_128, false);
						}
						hmac_instance = Signature.getInstance(Signature.ALG_HMAC_SHA_384, false);
						break;
					case MessageDigest.ALG_SHA_512:
						try {
							hmac_key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128, true);
						}
						catch(CryptoException e){
							hmac_key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128, false);
						}
						hmac_instance = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
						break;
				}
			}
	                catch(CryptoException exception){
				/* If we got an exception, this means that the card does not have a
				 * native HMAC support. Fallback to the software one!
				 */
				use_native_hmac = false;
			}
		}
		if(use_native_hmac == false){	
			if((ipad != null) || (opad != null) || (md_i != null) || (md_o != null)){
				CryptoException.throwIt(CryptoException.INVALID_INIT);
			}
			switch(digest_type){
				case MessageDigest.ALG_SHA_224:
				case MessageDigest.ALG_SHA_256:
				case MessageDigest.ALG_SHA_384:
				case MessageDigest.ALG_SHA_512:
	        	                md_i = MessageDigest.getInstance(digest_type, false);
					md_o = MessageDigest.getInstance(digest_type, false);
					local_md = MessageDigest.getInstance(digest_type, false);
					/**/
					ipad = JCSystem.makeTransientByteArray((short) (2 * md_i.getLength()), JCSystem.CLEAR_ON_DESELECT);
					opad = JCSystem.makeTransientByteArray((short) (2 * md_i.getLength()), JCSystem.CLEAR_ON_DESELECT);
					/**/
					if(USE_HMAC_MASKING == true){
						random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
						orig_ipad_masks = new byte[ipad.length];
						random.generateData(orig_ipad_masks, (short) 0, (short) orig_ipad_masks.length);
						orig_opad_masks = new byte[opad.length];
						random.generateData(orig_opad_masks, (short) 0, (short) orig_opad_masks.length);
						ipad_masks = JCSystem.makeTransientByteArray((short) ipad.length, JCSystem.CLEAR_ON_DESELECT);
						opad_masks = JCSystem.makeTransientByteArray((short) opad.length, JCSystem.CLEAR_ON_DESELECT);
					}
					/**/
					local_key = JCSystem.makeTransientByteArray((short) (md_i.getLength()), JCSystem.CLEAR_ON_DESELECT);
					dgst_i = JCSystem.makeTransientByteArray((short) (md_i.getLength()), JCSystem.CLEAR_ON_DESELECT);
					break;
				default:
					CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
			}
			digest = digest_type;
		}
	}

        public void hmac_init(byte[] key){
		if(use_native_hmac == true){
			hmac_key.setKey(key, (short) 0, (short) key.length);
			hmac_instance.init(hmac_key, Signature.MODE_SIGN);
	        	return;
		}
		else{
	                try {
				/* In order to limit a possible leakage of the key, we use some basic masking for ipad and opad */
				short i;
				md_i.reset();
				md_o.reset();
	
				if(USE_HMAC_MASKING == true){
					random.generateData(ipad_masks, (short) 0, (short) ipad_masks.length);
					for(i = 0; i < (short) ipad.length; i++){
						ipad[i] = (byte)(ipad_masks[i] ^ orig_ipad_masks[i]);
					}
					random.generateData(opad_masks, (short) 0, (short) opad_masks.length);
					for(i = 0; i < (short) opad.length; i++){
						opad[i] = (byte)(opad_masks[i] ^ orig_opad_masks[i]);
					}
				}
				
				if(key.length > ipad.length){
					/* Key length is > block size */
					local_md.reset();
					local_md.update(key, (short) 0, (short) key.length);
					/* [RB] NOTE: some javacard throw an exception when the input buffer is null even if the size is 0 ...
					 * Hence, we use a dummy value
					 */
					local_md.doFinal(ipad, (short) 0, (short) 0, local_key, (short) 0);
					for(i = 0; i < ipad.length; i++){
						if(i < local_key.length){
							if(USE_HMAC_MASKING == true){
								byte msk = (byte)(ipad_masks[i] ^ orig_ipad_masks[i] ^ 0x36);
								ipad[i] ^= (local_key[i] ^ msk);
								msk = (byte)(opad_masks[i] ^ orig_opad_masks[i] ^ 0x5c);
								opad[i] ^= (local_key[i] ^ msk);
							}
							else{
								ipad[i] = (byte)(local_key[i] ^ 0x36);
								opad[i] = (byte)(local_key[i] ^ 0x5c);
							}
						}
						else{
							if(USE_HMAC_MASKING == true){
								byte msk = (byte)(ipad_masks[i] ^ orig_ipad_masks[i] ^ 0x36);
								ipad[i] ^= msk;
								msk = (byte)(opad_masks[i] ^ orig_opad_masks[i] ^ 0x5c);
								opad[i] ^= msk;
							}
							else{
								ipad[i] = 0x36;
								opad[i] = 0x5c;
							}
						}
					}
				}
				else{
					/* Key length is <= block size */
					for(i = 0; i < ipad.length; i++){
						if(i < key.length){
							if(USE_HMAC_MASKING == true){
								byte msk = (byte)(ipad_masks[i] ^ orig_ipad_masks[i] ^ 0x36);
								ipad[i] ^= (key[i] ^ msk);
								msk = (byte)(opad_masks[i] ^ orig_opad_masks[i] ^ 0x5c);
								opad[i] ^= (key[i] ^ msk);
							}
							else{
								ipad[i] = (byte)(key[i] ^ 0x36);
								opad[i] = (byte)(key[i] ^ 0x5c);
							}
						}
						else{
							if(USE_HMAC_MASKING == true){
								byte msk = (byte)(ipad_masks[i] ^ orig_ipad_masks[i] ^ 0x36);
								ipad[i] ^= msk;
								msk = (byte)(opad_masks[i] ^ orig_opad_masks[i] ^ 0x5c);
								opad[i] ^= msk;
							}
							else{
								ipad[i] = 0x36;
								opad[i] = 0x5c;
							}
						}
					}
				}
				md_i.update(ipad, (short) 0, (short) ipad.length);
				md_o.update(opad, (short) 0, (short) opad.length);
	
	                        return;
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
	        	return;
		}
        }

        public void hmac_update(byte[] indata, short indataoffset, short indatalen){
		if(use_native_hmac == true){
			hmac_instance.update(indata, indataoffset, indatalen);
			return;
		}
		else{
	                try{
				/* Update the internal context */
				md_i.update(indata, indataoffset, indatalen);	
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
                	return;
		}
        }

        public short hmac_finalize(byte[] hmac, short hmac_offset){
		if(use_native_hmac == true){
			hmac_instance.sign(null, (short) 0, (short) 0, hmac, hmac_offset);
			return hmac_instance.getLength();
		}
		else{
	                try{
				if((md_i == null) || (md_o == null)){
					CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
				}
				/* Finalize the input hash */
				/* [RB] NOTE: some cards throw an exception when the input buffer is null even if the size is 0 ...
				 * Hence, we us a dummy value with ipad
				 */
				md_i.doFinal(ipad, (short) 0, (short) 0, dgst_i, (short) 0);
				md_o.doFinal(dgst_i, (short) 0, (short) dgst_i.length, hmac, hmac_offset);
				return md_o.getLength();
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

	public short hmac_len(){	
		if(use_native_hmac == true){
			return hmac_instance.getLength();
		}
		else{
			if((md_i == null) || (md_o == null)){
				CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
			}
			switch(digest){
				case MessageDigest.ALG_SHA_224:
					return 28;
				case MessageDigest.ALG_SHA_256:
					return 32;
				case MessageDigest.ALG_SHA_384:
					return 48;
				case MessageDigest.ALG_SHA_512:
					return 64;
				default:
					CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
			}
			return 0;
		}
	}
}
