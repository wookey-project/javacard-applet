package goodusb;

import javacard.framework.*;
import javacard.security.*;


public class JCDiffieHellman extends Applet
{
	/* Cruve parameters */
	private static Frp256v1 curve_params;
	/* The keys */
	private static Keys keys;
	/* Our key pair */
	private static KeyPair OurKeyPair;
	private static ECPrivateKey OurPrivKey;
	private static ECPublicKey OurPubKey;
	/* GoodUSB public key */
	private static KeyPair GoodUSBKeyPair;
	private static ECPublicKey GoodUSBPubKey;
	/* ECDH keypair */
	private static KeyPair kpECDH;
	private static ECPrivateKey privKeyECDH;
	private static ECPublicKey pubKeyECDH;
	/* The shared secret */
	private static byte[] ECDHSharedSecret;
	/* The secure channel parameters */
	private boolean secure_channel_initialized = false;
	private static byte[] IV;
	private static byte[] first_IV;
	private static byte[] AES_key;
	private static byte[] HMAC_key;
	private static byte[] PIN_key;	
	/* All the necessary buffers whose sizes are known */
	private static byte[] data;
	private static byte[] working_buffer;
	private static byte[] resp_sig;
	/* Various buffers */
	private static byte[] tmp;
	private static byte[] hmac;
	private static byte[] AES_key_prefix = { 'A', 'E', 'S', '_', 'S', 'E', 'S', 'S', 'I', 'O', 'N', '_', 'K', 'E', 'Y' };
	private static byte[] HMAC_key_prefix = { 'H', 'M', 'A', 'C', '_', 'S', 'E', 'S', 'S', 'I', 'O', 'N', '_', 'K', 'E', 'Y' };
	private static byte[] IV_prefix = { 'S', 'E', 'S', 'S', 'I', 'O', 'N', '_', 'I', 'V' };
	/* Dynamic PIN key prefix */
	private static byte[] PIN_KEY_prefix;
	/* Crypto contexts */
	private static KeyAgreement ecdh;
	private static Hmac hmac_ctx;
	private static Aes aes_ctx;
	private static Aes aes_ctx_cbc;
	private static Signature sigECDSA;
	private static MessageDigest md;
	/* PIN handling */
	private static byte[] default_pin = { (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38 };
	static OwnerPIN pin;
	/* Master key(s) */
	private static byte[] AES_ESSIV_master_key = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
						      (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
						      (byte) 0x20, (byte) 0x21, (byte) 0x22, (byte) 0x23, (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27,
						      (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37 };

	public static void install(byte[] bArray,
                               short bOffset, byte bLength)
	{
 		new JCDiffieHellman();
		initialize_eeprom();
		initialize_pin(default_pin);
	}

	protected JCDiffieHellman()
	{
		initialize_ram();
		register();
	}

	private short ecdh_shared_secret(byte[] shared_point, short indataoffset, short indatalen, byte[] shared_secret){

		try{
			// Generate our ECDH private and public parts
			kpECDH.genKeyPair();

	                ecdh.init(privKeyECDH);
			// First, we extract the point
			// Internal representation is an uncompressed point
			short sp_length = (short) (2 * (indatalen / 3) + 1);
			working_buffer[0] = 0x04;
        		Util.arrayCopyNonAtomic(shared_point, (short) indataoffset, working_buffer, (short) 1, (short) (sp_length - 1));
		
                	short len = ecdh.generateSecret(working_buffer, (short)0, (short) sp_length, shared_secret, (short) 0);

			// We override shared_point with our public key, which is d*G	
  			pubKeyECDH.getW(working_buffer, (short) 0);
        		Util.arrayCopyNonAtomic(working_buffer, (short) 1, shared_point, (short) 0, (short) (sp_length - 1));
				
			return len;
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

	private short ecdsa_sign(byte[] indata, short indataoffset, short indatalen, byte[] outdata, short outdataoffset){
		try{
			sigECDSA.init(OurPrivKey, Signature.MODE_SIGN);
			short structured_sequence_siglen = sigECDSA.sign(indata, (short) indataoffset, (short) indatalen, working_buffer, (short) 0);
			short r_size = 0;
			short s_size = 0;
			short siglen = 0;
			// FIXME: this is a lose way of decapsulating (r, s) from the SEQUENCE ASN.1 representation ...
			if(working_buffer[0] != 0x30){
                        	ISOException.throwIt((short) 0xAAE0);	
			}
			if(working_buffer[1] != (short)(structured_sequence_siglen - 2)){
                        	ISOException.throwIt((short) 0xAAE1);
			}
		
			if(working_buffer[2] != 0x02){
                        	ISOException.throwIt((short) 0xAAE2);
			}
			r_size = working_buffer[3];
			if(working_buffer[4] == 0x00){
				r_size--;
       	 			Util.arrayCopyNonAtomic(working_buffer, (short) 5, outdata, (short) outdataoffset, (short) r_size);
			}
			else{
       	 			Util.arrayCopyNonAtomic(working_buffer, (short) 4, outdata, (short) outdataoffset, (short) r_size);
			}
			siglen += r_size;
			if(working_buffer[(short)(4 + working_buffer[3])] != 0x02){
                        	ISOException.throwIt((short) 0xAAE3);
			}
			s_size = working_buffer[(short)(4 + working_buffer[3] + 1)];
			if(working_buffer[(short)(4 + working_buffer[3] + 2)] == 0x00){
				s_size--;
       	 			Util.arrayCopyNonAtomic(working_buffer, (short) (4 + working_buffer[3] + 3), outdata, (short) (outdataoffset + r_size), (short) s_size);
			}
			else{
       	 			Util.arrayCopyNonAtomic(working_buffer, (short) (4 + working_buffer[3] + 2), outdata, (short) (outdataoffset + r_size), (short) s_size);
			}
			siglen += s_size;
			return siglen;
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

	private boolean ecdsa_verify(APDU apdu, byte[] indata, short indataoffset, short indatalen, byte[] sigBuf, short sigoffset, short siglen){
		try{
			sigECDSA.init(GoodUSBPubKey, Signature.MODE_VERIFY);
			// The structured_sig buffer contains a structured (r, s) signature with an ASN.1 sequence
			// encapsulating two integers
			short r_length = (short) (siglen / 2);
			short s_length = (short) (siglen / 2);
			// FIXME: this is a lose way of encapsulating (r, s), and this will not work for very large integers
			working_buffer[0] = (byte) 0x30;
			working_buffer[1] = (byte) (siglen + 4);
			short s_offset = (short) 0;
			if((sigBuf[sigoffset] & ((byte) 0x80)) == 0x80){
				working_buffer[1]++;
				working_buffer[2] = 0x02;
				working_buffer[3] = (byte)(r_length + 1);
				working_buffer[4] = 0x00;
	        		Util.arrayCopyNonAtomic(sigBuf, (short) sigoffset, working_buffer, (short) 5, (short) r_length);
				s_offset = (short)(5 + r_length);
			}
			else{
				working_buffer[2] = 0x02;
				working_buffer[3] = (byte) (r_length);
	        		Util.arrayCopyNonAtomic(sigBuf, (short) sigoffset, working_buffer, (short) 4, (short) r_length);	
				s_offset = (short)(4 + r_length);
			}
			if((sigBuf[(short)(sigoffset + r_length)] & ((byte) 0x80)) == 0x80){
				working_buffer[1]++;
				working_buffer[s_offset] = 0x02;
				working_buffer[(short)(s_offset + 1)] = (byte)(s_length + 1);
				working_buffer[(short)(s_offset + 2)] = 0x00;
	        		Util.arrayCopyNonAtomic(sigBuf, (short) (sigoffset + r_length), working_buffer, (short) (s_offset + 3), (short) s_length);
			}
			else{
				working_buffer[s_offset] = 0x02;
				working_buffer[(short)(s_offset + 1)] = (byte)(s_length);
	        		Util.arrayCopyNonAtomic(sigBuf, (short) (sigoffset + r_length), working_buffer, (short) (s_offset + 2), (short) s_length);	
			}
			return sigECDSA.verify(indata, indataoffset, (short) indatalen, working_buffer, (short) 0, (short) (siglen + 6));
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
		return false;

	}

	static void initialize_pin(byte[] def_pin){
		pin = new OwnerPIN((byte) 3, (byte) 10);
		pin.update(def_pin, (short) 0, (byte) def_pin.length);
	}

	static void initialize_eeprom(){
		try {
			/* Initialize our long term variables */
			/* We do this in a transaction to be safer ... */
			JCSystem.beginTransaction();

			curve_params = new Frp256v1();
			keys = new Keys();

			byte[] p = curve_params.p;
			byte[] a = curve_params.a;
			byte[] b = curve_params.b;
			byte[] G = curve_params.G;
			byte[] q = curve_params.q;

			OurKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
			OurPrivKey = (ECPrivateKey) OurKeyPair.getPrivate();
			OurPubKey = (ECPublicKey) OurKeyPair.getPublic();

       			OurPrivKey.setFieldFP(p, (short) 0, (short) curve_params.p.length);
			OurPrivKey.setA(a, (short) 0, (short) a.length);
 			OurPrivKey.setB(b, (short) 0, (short) b.length);
			OurPrivKey.setG(G, (short) 0, (short) G.length);
			OurPrivKey.setR(q, (short) 0, (short) q.length);
			OurPrivKey.setS(keys.OurPrivKeyBuf, (short) 0, (short) keys.OurPrivKeyBuf.length);

			OurPubKey.setFieldFP(p, (short) 0, (short) curve_params.p.length);
			OurPubKey.setA(a, (short) 0, (short) a.length);
 			OurPubKey.setB(b, (short) 0, (short) b.length);
			OurPubKey.setG(G, (short) 0, (short) G.length);
			OurPubKey.setR(q, (short) 0, (short) q.length);
			OurPubKey.setW(keys.OurPubKeyBuf, (short) 0, (short) keys.OurPubKeyBuf.length);

			GoodUSBKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
			GoodUSBPubKey = (ECPublicKey) GoodUSBKeyPair.getPublic();
       			GoodUSBPubKey.setFieldFP(p, (short) 0, (short) curve_params.p.length);
			GoodUSBPubKey.setA(a, (short) 0, (short) a.length);
 			GoodUSBPubKey.setB(b, (short) 0, (short) b.length);
			GoodUSBPubKey.setG(G, (short) 0, (short) G.length);
			GoodUSBPubKey.setR(q, (short) 0, (short) q.length);
			GoodUSBPubKey.setW(keys.GoodUSBPubKeyBuf, (short) 0, (short) keys.GoodUSBPubKeyBuf.length);

			/* ECDH key pair */
       			kpECDH = new KeyPair(KeyPair.ALG_EC_FP,
        	       	            KeyBuilder.LENGTH_EC_FP_256);
			privKeyECDH = (ECPrivateKey) kpECDH.getPrivate();
      			pubKeyECDH = (ECPublicKey) kpECDH.getPublic();

			privKeyECDH.setFieldFP(p, (short) 0, (short) p.length);
  			privKeyECDH.setA(a, (short) 0, (short) a.length);
  			privKeyECDH.setB(b, (short) 0, (short) b.length);
  			privKeyECDH.setG(G, (short) 0, (short) G.length);
  			privKeyECDH.setR(q, (short) 0, (short) q.length);

  			pubKeyECDH.setFieldFP(p, (short) 0, (short) p.length);
  			pubKeyECDH.setA(a, (short) 0, (short) a.length);
  			pubKeyECDH.setB(b, (short) 0, (short) b.length);
  			pubKeyECDH.setG(G, (short) 0, (short) G.length);
  			pubKeyECDH.setR(q, (short) 0, (short) q.length);

			/* Initialize all the crypto algorithms contexts */
			ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
			hmac_ctx = new Hmac(MessageDigest.ALG_SHA_256);
			aes_ctx = new Aes((short)16, Aes.CTR);
			aes_ctx_cbc = new Aes((short)16, Aes.CBC);
			sigECDSA = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
			md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

			/* Initialize our PIN_key prefix, that is SHA-256 of the default PIN */
			md.reset();
			PIN_KEY_prefix = new byte[md.getLength()];
			md.doFinal(default_pin, (short) 0, (short) default_pin.length, PIN_KEY_prefix, (short) 0);

			/* Commit our transaction */
			JCSystem.commitTransaction();
		}
		catch(CryptoException exception)
        	{
		    /* Abort our transaction */
		    JCSystem.abortTransaction();
		    
        	    switch(exception.getReason()){
	                case CryptoException.ILLEGAL_USE:
                        	ISOException.throwIt((short) 0xBBD0);
                	        break;
        	        case CryptoException.ILLEGAL_VALUE:
	                        ISOException.throwIt((short) 0xBBD1);
        	                break;
	                case CryptoException.INVALID_INIT:
                	        ISOException.throwIt((short) 0xBBD2);
        	                break;
	                case CryptoException.NO_SUCH_ALGORITHM:
               	         	ISOException.throwIt((short) 0xBBD3);
        	                break;
	                case CryptoException.UNINITIALIZED_KEY:
                	        ISOException.throwIt((short) 0xBBD4);
	                        break;
        	       	default:
                        	ISOException.throwIt((short) 0xBBD5);
                        	break;
            		}
        	}
		catch(Exception e)
		{
		    /* Abort our transaction */
		    JCSystem.abortTransaction();
                    ISOException.throwIt((short) 0xBBD6);
		}

	}

	// Function to initialize in RAM (transient) variables
	static void initialize_ram(){
		/* Allocate all the buffers we need */
		data = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_DESELECT);
		working_buffer = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_DESELECT);
		resp_sig = JCSystem.makeTransientByteArray((short) (2 * 32), JCSystem.CLEAR_ON_DESELECT);
		ECDHSharedSecret = JCSystem.makeTransientByteArray((short) (32), JCSystem.CLEAR_ON_DESELECT);
		AES_key = JCSystem.makeTransientByteArray((short) (16), JCSystem.CLEAR_ON_DESELECT);
		HMAC_key = JCSystem.makeTransientByteArray((short) (32), JCSystem.CLEAR_ON_DESELECT);
		PIN_key = JCSystem.makeTransientByteArray((short) (32), JCSystem.CLEAR_ON_DESELECT);
		IV = JCSystem.makeTransientByteArray((short) (16), JCSystem.CLEAR_ON_DESELECT);
		first_IV = JCSystem.makeTransientByteArray((short) (16), JCSystem.CLEAR_ON_DESELECT);
		tmp = JCSystem.makeTransientByteArray((short) (32), JCSystem.CLEAR_ON_DESELECT);
		hmac = JCSystem.makeTransientByteArray((short) (32), JCSystem.CLEAR_ON_DESELECT);
	}

	// Function to initialize our secure channel using ECDH
	private void secure_channel_init(APDU apdu)
 	{
        	byte buffer[] = apdu.getBuffer();
	        short receivedLen = apdu.setIncomingAndReceive();
		short apdu_siglen = 2 * 32;
		short apdu_shared_point_len = 3 * 32;

        	Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), data, (short) 0, (short) receivedLen);

		/* Sanity check on the length */
		if(receivedLen != (short) (apdu_shared_point_len + apdu_siglen)){
			ISOException.throwIt((short) 0xBBD5);
		}
			
		if(ecdsa_verify(apdu, data, (short) 0, apdu_shared_point_len, data, (short) apdu_shared_point_len, apdu_siglen) == false){
			ISOException.throwIt((short) 0xAAAA);
		}
		
		// Compute the shared secret
		short secret_len = ecdh_shared_secret(data, (short) 0, (short) (3 * 32), ECDHSharedSecret);
		// Sign our response with our private ECDSA key
		short resp_sig_len = ecdsa_sign(data, (short) 0, (short) (3 * 32), data, (short) (3 * 32));

		try{
			// Our secure channel is initialized
			// AES session key
			md.reset();
			md.update(AES_key_prefix, (short) 0, (short) AES_key_prefix.length); 
			md.doFinal(ECDHSharedSecret, (short) 0, (short) secret_len, tmp, (short) 0);
        		Util.arrayCopyNonAtomic(tmp, (short) 0, AES_key, (short) 0, (short) 16);
			// HMAC session key
			md.reset();
			md.update(HMAC_key_prefix, (short) 0, (short) HMAC_key_prefix.length); 
			md.doFinal(ECDHSharedSecret, (short) 0, (short) secret_len, HMAC_key, (short) 0);
			// IV
			md.reset();
			md.update(IV_prefix, (short) 0, (short) IV_prefix.length); 
			md.doFinal(ECDHSharedSecret, (short) 0, (short) secret_len, tmp, (short) 0);
        		Util.arrayCopyNonAtomic(tmp, (short) 0, IV, (short) 0, (short) 16);
			// First IV
        		Util.arrayCopyNonAtomic(IV, (short) 0, first_IV, (short) 0, (short) 16);
			
			secure_channel_initialized = true;
		}
		catch(CryptoException exception)
        	{
        	    switch(exception.getReason()){
	                case CryptoException.ILLEGAL_USE:
                        	ISOException.throwIt((short) 0xBBD0);
                	        break;
        	        case CryptoException.ILLEGAL_VALUE:
	                        ISOException.throwIt((short) 0xBBD1);
        	                break;
	                case CryptoException.INVALID_INIT:
                	        ISOException.throwIt((short) 0xBBD2);
        	                break;
	                case CryptoException.NO_SUCH_ALGORITHM:
               	         	ISOException.throwIt((short) 0xBBD3);
        	                break;
	                case CryptoException.UNINITIALIZED_KEY:
                	        ISOException.throwIt((short) 0xBBD4);
	                        break;
        	       	default:
                        	ISOException.throwIt((short) 0xBBD5);
                        	break;
            		}
        	}
	        apdu.setOutgoing();
        	apdu.setOutgoingLength( (short) (apdu_shared_point_len + resp_sig_len));
       		apdu.sendBytesLong(data, (short) 0, (short) (apdu_shared_point_len + resp_sig_len));
	}

        private void increment_iv(){
                short i;
                for(i = (short)IV.length; i > 0; i--){
                        if(++IV[(short)(i - 1)] != 0){
                                break;
                        }
                }
        }

	private short receive_encrypted_apdu(APDU apdu, byte[] outdata){
	        short receivedLen = apdu.setIncomingAndReceive();
        	byte buffer[] = apdu.getBuffer();
		short OffsetCdata = apdu.getOffsetCdata();

		if(receivedLen < 32){
			return 0;
		}
		/* HMAC context */
		hmac_ctx.hmac_init(HMAC_key);
		/* Prepend the IV */
		hmac_ctx.hmac_update(IV, (short) 0, (short) IV.length);
		/* Append CLA, INS, P1, P2 */
		hmac_ctx.hmac_update(buffer, (short) ISO7816.OFFSET_CLA, (short) 4);
		if(receivedLen > 32){
			tmp[0] = (byte)(receivedLen - 32);
			hmac_ctx.hmac_update(tmp, (short) 0,  (short) 1);
			if(outdata == null){
				ISOException.throwIt((short) 0xAABB);
			}
			if(outdata.length < (short)(receivedLen - 32)){
				ISOException.throwIt((short) 0xAABB);
			}
			aes_ctx.aes_init(AES_key, IV, Aes.DECRYPT);
			aes_ctx.aes(buffer, (short) apdu.getOffsetCdata(), (short) (receivedLen - 32), outdata, (short) 0);
			hmac_ctx.hmac_update(buffer, (short) apdu.getOffsetCdata(),  (short) (receivedLen - 32));
		}
		else{
			increment_iv();
		}
		short recvLe = apdu.setOutgoing();
		if(recvLe != 256){
			/* We always expect Le = 256. If this is not the case, an error occured */
			ISOException.throwIt((short) 0xAABB);	
		}
		/* Le is added to the HMAC */
		tmp[0] = (byte)(0x00);
		hmac_ctx.hmac_update(tmp, (short) 0,  (short) 1);
		/* Finalize the HMAC */
		hmac_ctx.hmac_finalize(hmac, (short) 0);

		if(Util.arrayCompare(hmac, (short) 0, buffer, (short) (receivedLen - 32 + OffsetCdata), (short) hmac.length) != 0){
			ISOException.throwIt((short) 0xAACC);	
		}
		if(receivedLen <= 32){
			return 0;
		}
		else{
			return (short)(receivedLen - 32);
		}
	}

	private void send_encrypted_apdu(APDU apdu, byte[] indata, short indataoffset, short indatalen, byte sw1, byte sw2){
		if(secure_channel_initialized == false){
			/* If the secure channel is not initialized yet, we send an exception with SW1 and SW2 */
			ISOException.throwIt((short) (((short)sw1 << 8) ^ ((short)sw2)));
		}
		if(indata != null){
			if((short)(indataoffset + indatalen) > indata.length){
				return;
			}
		}
		/* HMAC context */
		hmac_ctx.hmac_init(HMAC_key);
		/* Prepend the IV when computing the HMAC */
		hmac_ctx.hmac_update(IV, (short) 0, (short) IV.length);
		/* Append SW1 and SW2 */
		tmp[0] = (byte)sw1;
		tmp[1] = (byte)sw2;
		hmac_ctx.hmac_update(tmp, (short) 0, (short) 1);
		hmac_ctx.hmac_update(tmp, (short) 1, (short) 1);
		if(indatalen > 0){
			aes_ctx.aes_init(AES_key, IV, Aes.DECRYPT);
			aes_ctx.aes(indata, (short) 0, (short) indatalen, working_buffer, (short) 0);
			tmp[0] = (byte)indatalen;
			hmac_ctx.hmac_update(tmp, (short) 0, (short) 1);
			hmac_ctx.hmac_update(working_buffer, (short) 0, (short) indatalen);
		}
		else{
			increment_iv();
		}
		hmac_ctx.hmac_finalize(working_buffer, (short) indatalen);

		if(apdu.getCurrentState() != APDU.STATE_OUTGOING){
			apdu.setOutgoing();
		}
        	apdu.setOutgoingLength((short) (indatalen + 32));
                apdu.sendBytesLong(working_buffer, (short) 0, (short) (indatalen + 32));
		if((sw1 != 0x90) && (sw2 != 0x00)){
			ISOException.throwIt((short) (((short)sw1 << 8) ^ ((short)sw2)));
		}

		return;
	}

	// ECHO test in the secure channel (FIXME: to be removed, for debug purposes)
	private void secure_channel_echo_test(APDU apdu){
		if(secure_channel_initialized == false){
			send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0xd6, (byte) 0x00);
		}
		short outdata_len = receive_encrypted_apdu(apdu, data);
		send_encrypted_apdu(apdu, data, (short) 0, (short) outdata_len, (byte) 0x90, (byte) 0x00);
	}

	public void check_pin(APDU apdu){
		/* The user is sending his pin, the secure channel must be initialized */
		if(secure_channel_initialized == false){
			send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0xd7, (byte) 0x00);
		}
		short data_len = receive_encrypted_apdu(apdu, data);
		/* Get the real pin length (the PIN is padded to 16 bytes, the last byte represents the size) */
		if(data_len != 16){
			/* Bad length, decrement and respond an error */
			try {
				pin.check(null, (short) 0, (byte) 0);
			}
			catch(Exception e){
				/* We have forced a NullPointerException to decrement our counter */
			}
			send_encrypted_apdu(apdu, data, (short) 0, (short) 1, (byte) 0xd7, (byte) 0x01);
		}
		short pin_len = data[15];
		
		/* We have the pin, check it! */
		if(pin.check(data, (short) 0, (byte) pin_len) == false){
			/* Was this the last hope? */
			byte tries = pin.getTriesRemaining();
			if(tries == 0){
				/* Card is blocked ... */
				data[0] = tries;
				send_encrypted_apdu(apdu, data, (short) 0, (short) 1, (byte) 0xd7, (byte) 0x02);
			}
			else{
				/* Respond an error with the number of remaining tries */
				data[0] = tries;
				send_encrypted_apdu(apdu, data, (short) 0, (short) 1, (byte) 0xd7, (byte) 0x03);
			}
		}
		else{
			md.reset();
			md.update(data, (short) 0, (short) 16); 
			/* PIN is OK: send that all is good, with the remaining pins as information */
			data[0] = pin.getTriesRemaining();
			send_encrypted_apdu(apdu, data, (short) 0, (short) 1, (byte) 0x90, (byte) 0x00);
			/* We also adapt ou AES and HMAC session keys using an information derived from the padded PIN:
			 * we mask our previous session keys with a hash of the padded PIN concatenated with the IV
			 */
			md.doFinal(IV, (short) 0, (short) IV.length, tmp, (short) 0);
			short i;
			for(i = 0; i < AES_key.length; i++){
				AES_key[i] = (byte)(AES_key[i] ^ tmp[i]);
			}
			for(i = 0; i < HMAC_key.length; i++){
				HMAC_key[i] = (byte)(HMAC_key[i] ^ tmp[i]);
			}
			
			return;
		}	
	}

	public void set_pin(APDU apdu){
		/* The user asks to change his pin, the secure channel must be initialized */
		if(secure_channel_initialized == false){
			send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0xd8, (byte) 0x00);
		}
		short data_len = receive_encrypted_apdu(apdu, data);
		/* We check that we are already unlocked */
		if(pin.isValidated() == false){
			/* We are not authenticated, ask for an authentication */
			send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0xd8, (byte) 0x01);
		}
		else{
			/* Try to change the pin */
			/* Get the real pin length (the PIN is padded to 16 bytes, the last byte represents the size) */
			if(data_len != 16){
				/* Bad length, respond an error */
				send_encrypted_apdu(apdu, data, (short) 0, (short) 1, (byte) 0xd8, (byte) 0x02);
			}
			short pin_len = data[15];

			/* Check new pin real length */
			if((pin_len < 4) || (pin_len > 15)){
				send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0xd8, (byte) 0x03);
			}
			else{
				/* Update the PIN */
				pin.update(data, (short) 0, (byte) pin_len);
				send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0x90, (byte) 0x00);
				/* Update the PIN Key prefix */
				md.reset();
				md.doFinal(data, (short) 0, (short) pin_len, PIN_KEY_prefix, (short) 0);
			}	
		}

	}

	public void lock_token(APDU apdu){
		/* The user asks to lock the token, the secure channel must be initialized */
		if(secure_channel_initialized == false){
			send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0xd9, (byte) 0x00);
		}
		short data_len = receive_encrypted_apdu(apdu, data);
		/* If the session is not unlocked, we have nothing to do, else we lock it */
		if(pin.isValidated() == true){
			/* Note: we reset the pin. The side effect is a try counter reset, bu this is OK
			 * since an unlocked session means a reset of the counters anyways.
			 */
			pin.reset();
		}
		send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0x90, (byte) 0x00);
	}

	public void get_key(APDU apdu){
		/* The user asks to get the master key and its derivative, the secure channel must be initialized */
		if(secure_channel_initialized == false){
			send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0xda, (byte) 0x00);
		}
		short data_len = receive_encrypted_apdu(apdu, data);
		/* We check that we are already unlocked */
		if(pin.isValidated() == false){
			/* We are not authenticated, ask for an authentication */
			send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0xda, (byte) 0x01);
		}
		else if(data_len != 0){
			/* We should not receive data in this command */
			send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0xda, (byte) 0x02);
		}
		else{
			/* We can send the key and its derivative. In order to avoid fault attacks, we encrypt
			 * them with a key derived from the 'real' PIN: a 128-bit AES key as the first half of
			 * SHA-256(first_IV || PIN_KEY_prefix) = SHA-256(first_IV || SHA-256(PIN))
			 */
			md.reset();
			md.update(first_IV, (short) 0, (short) first_IV.length);
			md.doFinal(PIN_KEY_prefix, (short) 0, (short) PIN_KEY_prefix.length, PIN_key, (short) 0);
			/* We send an encrypted buffer of 64 bytes composed of Key || SHA-256(Key) */
        		Util.arrayCopyNonAtomic(AES_ESSIV_master_key, (short) 0, data, (short) 0, (short) AES_ESSIV_master_key.length);
			md.reset();
			md.doFinal(AES_ESSIV_master_key, (short) 0, (short) AES_ESSIV_master_key.length, data, (short) AES_ESSIV_master_key.length);
			/* AES-128 CBC encrypt */
			aes_ctx_cbc.aes_init(PIN_key, IV, Aes.DECRYPT);
			aes_ctx_cbc.aes(data, (short) 0, (short) 64, data, (short) 0);
			/* Now send the encrypted APDU */
			send_encrypted_apdu(apdu, data, (short) 0, (short) 64, (byte) 0x90, (byte) 0x00);
		}
	}

	public void process(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();

		if (selectingApplet()){
			return;
		}

		if(buffer[ISO7816.OFFSET_CLA] != (byte)0x00)
			ISOException.throwIt((short) 0x6660);

		switch (buffer[ISO7816.OFFSET_INS])
		{
			/* D5 = initialize our secure channel */
			case (byte)0xD5:
				secure_channel_init(apdu);
				return;
			case (byte)0xD6:
				secure_channel_echo_test(apdu);
				return;
			case (byte)0xD7:
				check_pin(apdu);
				return;
			case (byte)0xD8:
				set_pin(apdu);
				return;
			case (byte)0xD9:
				lock_token(apdu);
				return;
			case (byte)0xDA:
				get_key(apdu);
				return;

/*
			case (byte)0xD1:
				processINSD1(apdu);
				return;
			case (byte)0xD2:
				processINSD2(apdu);
				return;
			case (byte)0xD3:
				processINSD3(apdu);
				return;
			case (byte)0xD4:
				processINSD4(apdu);
 				return;
*/
			default:
				ISOException.throwIt((short) 0x6661);
		}

	}
}

