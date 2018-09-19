package goodusb;

import javacard.framework.*;
import javacard.security.*;

public class Hmac {
	/* The message digest instances */
	private MessageDigest md_i = null;
	private MessageDigest md_o = null;
	private MessageDigest local_md = null;
	private byte[] ipad = null;
	private byte[] opad = null;
	private byte[] local_key;
	private byte[] dgst_i;

	protected Hmac(byte digest_type){
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
				ipad = JCSystem.makeTransientByteArray((short) (2 * md_i.getLength()), JCSystem.CLEAR_ON_DESELECT);
				opad = JCSystem.makeTransientByteArray((short) (2 * md_i.getLength()), JCSystem.CLEAR_ON_DESELECT);
				local_key = JCSystem.makeTransientByteArray((short) (md_i.getLength()), JCSystem.CLEAR_ON_DESELECT);
				dgst_i = JCSystem.makeTransientByteArray((short) (md_i.getLength()), JCSystem.CLEAR_ON_DESELECT);
				break;
			default:
				CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
			}
	}

        public void hmac_init(byte[] key){
                try {
			short i;
			md_i.reset();
			md_o.reset();
			Util.arrayFillNonAtomic(ipad, (short) 0, (short)ipad.length, (byte) 0x36);
			Util.arrayFillNonAtomic(opad, (short) 0, (short)opad.length, (byte) 0x5c);
			
			if(key.length > ipad.length){
				/* Key length is > block size */
				local_md.reset();
				local_md.update(key, (short) 0, (short) key.length);
				local_md.doFinal(null, (short) 0, (short) 0, local_key, (short) 0);
				for(i = 0; i < local_key.length; i++){
					ipad[i] ^= local_key[i];
					opad[i] ^= local_key[i];
				}
			}
			else{
				/* Key length is <= block size */
				for(i = 0; i < key.length; i++){
					ipad[i] ^= key[i];
					opad[i] ^= key[i];
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

        public void hmac_update(byte[] indata, short indataoffset, short indatalen){
                try{
			/* Update the internal context */
			md_i.update(indata, (short) indataoffset, (short) indatalen);	
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

        public short hmac_finalize(byte[] hmac, short hmac_offset){
                try{
			if((md_i == null) || (md_o == null)){
				CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
			}
			/* Finalize the input hash */
			md_i.doFinal(null, (short) 0, (short) 0, dgst_i, (short) 0);
			md_o.doFinal(dgst_i, (short) 0, (short) dgst_i.length, hmac, (short) hmac_offset);
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
