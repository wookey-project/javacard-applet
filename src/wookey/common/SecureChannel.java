import javacard.framework.*;
import javacard.security.*;


public class SecureChannel {
	/* Cruve parameters */
	public ECCurves ec_context = null;
	/* Our key pair */
	private ECKeyPair OurKeyPairWrapper = null;
	private KeyPair OurKeyPair = null;
	private ECPrivateKey OurPrivKey = null;
	private ECPublicKey OurPubKey = null;
	/* WooKey public key */
	private ECKeyPair WooKeyKeyPairWrapper = null;
	private KeyPair WooKeyKeyPair = null;
	private ECPublicKey WooKeyPubKey = null;
	/* The shared secret (derived from the ECDH) */
	private byte[] ECDHSharedSecret = null;
	/* The secure channel parameters */
	private byte[] secure_channel_initialized = null;
	private byte[] IV = null;
	private byte[] first_IV = null;
	private byte[] AES_key = null;
	private byte[] HMAC_key = null;
	private byte[] PIN_key = null;
	/* All the necessary buffers whose sizes are known */
	public byte[] working_buffer = null; /* this is a scratchpad buffer for operations using temporary memory */
	/* Various buffers */
	private byte[] tmp = null;
	private byte[] hmac = null;
	private static final byte[] AES_key_prefix = { 'A', 'E', 'S', '_', 'S', 'E', 'S', 'S', 'I', 'O', 'N', '_', 'K', 'E', 'Y' };
	private static final byte[] HMAC_key_prefix = { 'H', 'M', 'A', 'C', '_', 'S', 'E', 'S', 'S', 'I', 'O', 'N', '_', 'K', 'E', 'Y' };
	private static final byte[] IV_prefix = { 'S', 'E', 'S', 'S', 'I', 'O', 'N', '_', 'I', 'V' };
	/* Dynamic PIN key prefix */
	private byte[] PIN_KEY_prefix = null;
	/* Crypto contexts (note: the ECC contexts are handled by the ECC layer) */
	private Hmac hmac_ctx = null;
	private Aes aes_ctx = null;
	private Aes aes_ctx_cbc = null;
	private MessageDigest md = null;

	protected SecureChannel(byte[] default_pin, byte[] OurPrivKeyBuf, byte[] OurPubKeyBuf, byte[] WooKeyPubKeyBuf, byte[] LibECCparams)
	{
		/* Initialize the keys and other crypto contexts */
		initialize_eeprom(default_pin, OurPrivKeyBuf, OurPubKeyBuf, WooKeyPubKeyBuf, LibECCparams);
		initialize_ram();
	}

	public void initialize_eeprom(byte[] default_pin, byte[] OurPrivKeyBuf, byte[] OurPubKeyBuf, byte[] WooKeyPubKeyBuf, byte[] LibECCparams){
		try {
			/* Initialize our long term variables */
			/* We do this in a transaction to be safer ... */
			JCSystem.beginTransaction();

			/* Initialize all the crypto algorithms contexts */
			hmac_ctx = new Hmac(MessageDigest.ALG_SHA_256);
			aes_ctx = new Aes((short)16, Aes.CTR);
			aes_ctx_cbc = new Aes((short)16, Aes.CBC);
			md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

			/* Initialize our PIN_key prefix, that is SHA-256 of the default PIN */
			PIN_KEY_prefix = new byte[md.getLength()];
			update_pin_key(default_pin, (byte)default_pin.length);

			/* Initialize the ECC context */
			ec_context = new ECCurves(LibECCparams);

			/* Import the ECC keys */
			OurKeyPairWrapper = new ECKeyPair();
			ec_context.initialize_EC_key_pair_context(OurPrivKeyBuf, false, OurPubKeyBuf, OurKeyPairWrapper);
			OurKeyPair = OurKeyPairWrapper.kp;
			OurPrivKey = OurKeyPairWrapper.PrivKey;
			OurPubKey  = OurKeyPairWrapper.PubKey;
       			
			WooKeyKeyPairWrapper = new ECKeyPair();
			ec_context.initialize_EC_key_pair_context(null, false, WooKeyPubKeyBuf, WooKeyKeyPairWrapper);
			WooKeyKeyPair = WooKeyKeyPairWrapper.kp;
			WooKeyPubKey  = WooKeyKeyPairWrapper.PubKey;

			/* Commit our transaction */
			JCSystem.commitTransaction();
		}
		catch(CryptoException exception)
        	{
		    /* Abort our transaction */
		    JCSystem.abortTransaction();
		    
        	    switch(exception.getReason()){
	                case CryptoException.ILLEGAL_USE:
                        	ISOException.throwIt((short) 0x6BD0);
                	        break;
        	        case CryptoException.ILLEGAL_VALUE:
	                        ISOException.throwIt((short) 0x6BD1);
        	                break;
	                case CryptoException.INVALID_INIT:
                	        ISOException.throwIt((short) 0x6BD2);
        	                break;
	                case CryptoException.NO_SUCH_ALGORITHM:
               	         	ISOException.throwIt((short) 0x6BD3);
        	                break;
	                case CryptoException.UNINITIALIZED_KEY:
                	        ISOException.throwIt((short) 0x6BD4);
	                        break;
        	       	default:
                        	ISOException.throwIt((short) 0x6BD5);
                        	break;
            		}
        	}
		catch(Exception e)
		{
		    /* Abort our transaction */
		    JCSystem.abortTransaction();
                    ISOException.throwIt((short) 0x6BD6);
		}

	}

	/* Function to initialize in RAM (transient) variables */
	public void initialize_ram(){
		short BN_len = (short) ec_context.p.length;

		/* Allocate all the buffers we need */
		secure_channel_initialized = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
		secure_channel_initialized[0] = secure_channel_initialized[1] = (byte)0x00;
		working_buffer = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_DESELECT);
		ECDHSharedSecret = JCSystem.makeTransientByteArray(BN_len, JCSystem.CLEAR_ON_DESELECT);
		/* AES-128 CTR key */
		AES_key = JCSystem.makeTransientByteArray((short) (16), JCSystem.CLEAR_ON_DESELECT);
		/* HMAC-SHA-256 key */
		HMAC_key = JCSystem.makeTransientByteArray((short) (32), JCSystem.CLEAR_ON_DESELECT);
		/* AES-128 CBC key (it is 256-bits since it is a result of SHA-256, but we only take
		   the first half)
		 */
		PIN_key = JCSystem.makeTransientByteArray((short) (32), JCSystem.CLEAR_ON_DESELECT);
		IV = JCSystem.makeTransientByteArray((short) (16), JCSystem.CLEAR_ON_DESELECT);
		first_IV = JCSystem.makeTransientByteArray((short) (16), JCSystem.CLEAR_ON_DESELECT);
		tmp = JCSystem.makeTransientByteArray(BN_len, JCSystem.CLEAR_ON_DESELECT);
	}

	public boolean is_secure_channel_initialized(){
		if((secure_channel_initialized[0] == (byte)0xaa) && (secure_channel_initialized[1] == (byte)0x55)){
			return true;
		}
		return false;
	}

	private void set_secure_channel_opened(){
		/* Make this a transaction */
                JCSystem.beginTransaction();
		secure_channel_initialized[0] = (byte)0xaa;
		secure_channel_initialized[1] = (byte)0x55;	
		JCSystem.commitTransaction();
		return;
	}

	public void close_secure_channel(){
		secure_channel_initialized[0] = secure_channel_initialized[1] = (byte)0x00;
		/* Erase our local sensitive data */
		Util.arrayFillNonAtomic(ECDHSharedSecret, (short) 0, (short) ECDHSharedSecret.length, (byte) 0);
		Util.arrayFillNonAtomic(AES_key, (short) 0, (short) AES_key.length, (byte) 0);
		Util.arrayFillNonAtomic(HMAC_key, (short) 0, (short) HMAC_key.length, (byte) 0);
		Util.arrayFillNonAtomic(PIN_key, (short) 0, (short) PIN_key.length, (byte) 0);
		Util.arrayFillNonAtomic(IV, (short) 0, (short) IV.length, (byte) 0);
		Util.arrayFillNonAtomic(first_IV, (short) 0, (short) first_IV.length, (byte) 0);
		Util.arrayFillNonAtomic(tmp, (short) 0, (short) tmp.length, (byte) 0);
		Util.arrayFillNonAtomic(working_buffer, (short) 0, (short) working_buffer.length, (byte) 0);
	}

	/* Function to initialize our secure channel using ECDH */
	public void secure_channel_init(APDU apdu, byte[] data)
 	{
		short BN_len = (short) ec_context.p.length;
        	byte buffer[] = apdu.getBuffer();
	        short receivedLen = apdu.setIncomingAndReceive();
		short apdu_siglen = (short)(2 * BN_len);
		short apdu_shared_point_len = (short)(3 * BN_len);

        	Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), data, (short) 0, receivedLen);

		/* Sanity check on the length */
		if(receivedLen != (short) (apdu_shared_point_len + apdu_siglen)){
			CryptoException.throwIt(CryptoException.ILLEGAL_USE);
		}

		if(ec_context.ecdsa_verify(data, (short) 0, apdu_shared_point_len, data, apdu_shared_point_len, apdu_siglen, working_buffer, WooKeyPubKey) == false){
			CryptoException.throwIt(CryptoException.ILLEGAL_USE);
		}
		/* Compute the shared secret */
		short secret_len = ec_context.ecdh_shared_secret(data, (short) 0, (short) (3 * BN_len), ECDHSharedSecret, working_buffer);
		/* Sign our response with our private ECDSA key */
		short resp_sig_len = ec_context.ecdsa_sign(data, (short) 0, (short) (3 * BN_len), data, (short) (3 * BN_len), working_buffer, OurPrivKey);

		try{
			/* Our secure channel is initialized
			 * AES session key
			 */
			md.reset();
			md.update(AES_key_prefix, (short) 0, (short) AES_key_prefix.length); 
			md.doFinal(ECDHSharedSecret, (short) 0, secret_len, tmp, (short) 0);
        		Util.arrayCopyNonAtomic(tmp, (short) 0, AES_key, (short) 0, (short) 16);
			/* HMAC session key */
			md.reset();
			md.update(HMAC_key_prefix, (short) 0, (short) HMAC_key_prefix.length); 
			md.doFinal(ECDHSharedSecret, (short) 0, secret_len, HMAC_key, (short) 0);
			/* IV */
			md.reset();
			md.update(IV_prefix, (short) 0, (short) IV_prefix.length); 
			md.doFinal(ECDHSharedSecret, (short) 0, secret_len, tmp, (short) 0);
        		Util.arrayCopyNonAtomic(tmp, (short) 0, IV, (short) 0, (short) 16);
			/* First IV */
        		Util.arrayCopyNonAtomic(IV, (short) 0, first_IV, (short) 0, (short) 16);

			/* Secure channel is opened */
			set_secure_channel_opened();
		}
		catch(CryptoException e)
        	{
		    CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        	}
	        apdu.setOutgoing();
        	apdu.setOutgoingLength( (short) (apdu_shared_point_len + resp_sig_len));
       		apdu.sendBytesLong(data, (short) 0, (short) (apdu_shared_point_len + resp_sig_len));
	}

        private void increment_iv(){
                short i;
		byte end = 0, dummy = 0;
                for(i = (short)IV.length; i > 0; i--){
                        if(end == 0){
				if((++IV[(short)(i - 1)] != 0)){
					end = 1;
				}
                        }
			else{
				dummy++;
			}
                }
        }
        private void add_iv(short num){
                short i;
                for(i = 0; i < num; i++){
			increment_iv();
                }
        }
	public short get_max_sc_apdu_len(){
		return (short)(255 - hmac_ctx.hmac_len());
	}
	public short receive_encrypted_apdu(APDU apdu, byte[] outdata){
	        short receivedLen = apdu.setIncomingAndReceive();
        	byte buffer[] = apdu.getBuffer();
		short OffsetCdata = apdu.getOffsetCdata();
		short hmac_len = hmac_ctx.hmac_len();

		if(hmac_len == 0){
			close_secure_channel();
			ISOException.throwIt((short) 0xAAAA);	
		}
		if(receivedLen < hmac_len){
			close_secure_channel();
			ISOException.throwIt((short) 0xAAAA);
		}
		/* HMAC context */
		hmac_ctx.hmac_init(HMAC_key);
		/* Prepend the IV */
		hmac_ctx.hmac_update(IV, (short) 0, (short) IV.length);
		/* Append CLA, INS, P1, P2 */
		hmac_ctx.hmac_update(buffer, (short) ISO7816.OFFSET_CLA, (short) 4);
		if(receivedLen > hmac_len){
			tmp[0] = (byte)(receivedLen - hmac_len);
			hmac_ctx.hmac_update(tmp, (short) 0,  (short) 1);
			if(outdata == null){
				close_secure_channel();
				ISOException.throwIt((short) 0xAABB);
			}
			if(outdata.length < (short)(receivedLen - hmac_len)){
				close_secure_channel();
				ISOException.throwIt((short) 0xAABA);
			}
			aes_ctx.aes_init(AES_key, IV, Aes.DECRYPT);
			aes_ctx.aes(buffer, apdu.getOffsetCdata(), (short) (receivedLen - hmac_len), outdata, (short) 0);
	                /* Increment the IV by as many blocks as necessary */
			add_iv((short) ((short) (receivedLen - hmac_len) / Aes.AES_BLOCK_SIZE));
			hmac_ctx.hmac_update(buffer, apdu.getOffsetCdata(),  (short) (receivedLen - hmac_len));
		}
		/* Always increment the IV for the next data to send/receive */
		increment_iv();
		short recvLe = apdu.setOutgoing();
		if(recvLe != 256){
			/* We always expect Le = 256. If this is not the case, an error occured */
			close_secure_channel();
			ISOException.throwIt((short) 0xAABC);
		}
		/* Le is added to the HMAC */
		tmp[0] = (byte)(0x00);
		hmac_ctx.hmac_update(tmp, (short) 0,  (short) 1);
		/* Finalize the HMAC */
		hmac_ctx.hmac_finalize(working_buffer, (short) 0);

		if(Util.arrayCompare(working_buffer, (short) 0, buffer, (short) (receivedLen - hmac_len + OffsetCdata), hmac_len) != 0){
			close_secure_channel();
			ISOException.throwIt((short) 0xAACC);	
		}
		if(receivedLen < hmac_len){
			close_secure_channel();
			ISOException.throwIt((short) 0xAADD);	
		}
		else{
			return (short)(receivedLen - hmac_len);
		}
		/* Default return (should end up here in case of error) */
		return 0;
	}

	public void send_encrypted_apdu(APDU apdu, byte[] indata, short indataoffset, short indatalen, byte sw1, byte sw2){
		if(is_secure_channel_initialized() == false){
			/* If the secure channel is not initialized yet, we send an exception with SW1 and SW2 */
			ISOException.throwIt((short) (((short)sw1 << 8) ^ (short)(sw2 & 0x00ff)));
		}
		if(indata != null){
			if((short)(indataoffset + indatalen) > indata.length){
				close_secure_channel();
				ISOException.throwIt((short) (((short)sw1 << 8) ^ (short)(sw2 & 0x00ff)));
			}
		}
		short hmac_len = hmac_ctx.hmac_len();
		if(hmac_len == 0){
			close_secure_channel();
			ISOException.throwIt((short) (((short)sw1 << 8) ^ (short)(sw2 & 0x00ff)));
		}

		/* HMAC context */
		hmac_ctx.hmac_init(HMAC_key);
		/* Prepend the IV when computing the HMAC */
		hmac_ctx.hmac_update(IV, (short) 0, (short) IV.length);
		/* Append SW1 and SW2 */
		tmp[0] = sw1;
		tmp[1] = sw2;
		hmac_ctx.hmac_update(tmp, (short) 0, (short) 1);
		hmac_ctx.hmac_update(tmp, (short) 1, (short) 1);
		if(indatalen > 0){
			aes_ctx.aes_init(AES_key, IV, Aes.DECRYPT);
			aes_ctx.aes(indata, (short) 0, indatalen, working_buffer, (short) 0);
	                /* Increment the IV by as many blocks as necessary */
			add_iv((short) (indatalen / Aes.AES_BLOCK_SIZE));
			tmp[0] = (byte)indatalen;
			hmac_ctx.hmac_update(tmp, (short) 0, (short) 1);
			hmac_ctx.hmac_update(working_buffer, (short) 0, indatalen);
		}
		/* Always increment the IV for the next data to send/receive */
		increment_iv();

		hmac_ctx.hmac_finalize(working_buffer, indatalen);

		if(apdu.getCurrentState() != APDU.STATE_OUTGOING){
			apdu.setOutgoing();
		}
        	apdu.setOutgoingLength((short) (indatalen + hmac_len));
                apdu.sendBytesLong(working_buffer, (short) 0, (short) (indatalen + hmac_len));
		if((sw1 != (byte)0x90) || (sw2 != (byte)0x00)){
			ISOException.throwIt((short) (((short)sw1 << 8) ^ (short)(sw2 & 0x00ff)));
		}

		return;
	}


	public void adapt_keys(byte[] input){
        	/* We also adapt ou AES and HMAC session keys using an information derived from the padded PIN:
         	 * we mask our previous session keys with a hash of the padded PIN concatenated with the IV
         	 */
		md.reset();
		md.update(input, (short) 0, (short) 16);
         	md.doFinal(IV, (short) 0, (short) IV.length, tmp, (short) 0);
         	short i;
         	for(i = 0; i < AES_key.length; i++){
                	AES_key[i] = (byte)(AES_key[i] ^ tmp[i]);
         	}
         	for(i = 0; i < HMAC_key.length; i++){
                	HMAC_key[i] = (byte)(HMAC_key[i] ^ tmp[i]);
         	}
	}
	
	public void update_pin_key(byte[] pin, byte pin_len){
                /* Update the PIN Key prefix */
                md.reset();
                md.doFinal(pin, (short) 0, (short) pin_len, PIN_KEY_prefix, (short) 0);
	}

	public void pin_encrypt_sensitive_data(byte[] input, byte[] output, short input_offset, short output_offset, short len){
                /* In order to avoid fault attacks, we encrypt sensitive data
                 * with a key derived from the 'real' PIN: a 128-bit AES key as the first half of
                 * SHA-256(first_IV || PIN_KEY_prefix) = SHA-256(first_IV || SHA-256(PIN))
                 */
		md.reset();
		md.update(first_IV, (short) 0, (short) first_IV.length);
		md.doFinal(PIN_KEY_prefix, (short) 0, (short) PIN_KEY_prefix.length, PIN_key, (short) 0);
		/* AES-128 CBC encrypt */
		aes_ctx_cbc.aes_init(PIN_key, IV, Aes.ENCRYPT);
		aes_ctx_cbc.aes(input, input_offset, len, output, output_offset);
	}
}

