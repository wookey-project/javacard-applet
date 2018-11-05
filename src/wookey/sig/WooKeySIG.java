package wookey_sig;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;

/* NOTE: because of memory usage, we use the underlying EC class of the Secure Channel. This
 * should not be an issue since the underlying EC parameters for ECDSA are exactly the same for the
 * secure channel and for the ECDSA signature.
 */
public class WooKeySIG extends Applet implements ExtendedLength
{
	/* Our common WooKey class */
	private static WooKey W = null;

	/* Random data instance */
	private static RandomData random = null;
	/* The signature private and public keys */
	private static ECKeyPair SigKeyPairWrapper = null;
	private static KeyPair SigKeyPair = null;
	private static ECPrivateKey SigPrivKey = null;
	private static ECPublicKey SigPubKey = null;
	/* HMAC contexts */
	private static Hmac hmac_ctx = null;
	/* AES context */
	private static Aes aes_ctx = null;
	/* Useful tmp buffer */
	private static byte[] tmp = null;

	/* Counter to limit the global number of chunks in one session */
	private static short num_chunks = 0;
	final static short MAX_NUM_CHUNKS = (short)0xffff;

	/* The local state of the applet:
	 * We expect the first APDU to come to be the one "opening" a
         * signing session TOKEN_INS_BEGIN_SIGN_SESSION, then as many  
	 * TOKEN_INS_DERIVE_KEY as necessary, then (and only then) a
	 * TOKEN_INS_SIGN_FIRMWARE closing the session.
	 */
	private static byte[] wookeysig_state = null;
	/* The session IV */
	private static byte[] sign_session_IV = null;
	
        /* Instructions specific to the SIG applet */
        public static final byte TOKEN_INS_BEGIN_SIGN_SESSION = (byte) 0x30;
        public static final byte TOKEN_INS_DERIVE_KEY = (byte) 0x31;
        public static final byte TOKEN_INS_SIGN_FIRMWARE = (byte) 0x32;
        public static final byte TOKEN_INS_VERIFY_FIRMWARE = (byte) 0x33;
        public static final byte TOKEN_INS_GET_SIG_TYPE = (byte) 0x34;

	public static void install(byte[] bArray,
                               short bOffset, byte bLength)
	{
		/* HMAC context */
		hmac_ctx = new Hmac(MessageDigest.ALG_SHA_256);
		/* AES context */
		aes_ctx = new Aes((short)16, Aes.CBC);
		/* The local variable handling our state */
		wookeysig_state = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
		wookeysig_state[0] = wookeysig_state[1] = 0;
		sign_session_IV = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		/* Random instance */
		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		/* Our working temporary buffer */
		tmp = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
 		new WooKeySIG();
	}

	protected WooKeySIG()
	{
		register();
	}

	/* Function that makes the chunk session IV evolve. We use a simple inrementation of the IV at each step. */
	private void next_iv(){
                short i;
                byte end = 0, dummy = 0;
                for(i = (short)sign_session_IV.length; i > 0; i--){
                        if(end == 0){
                                if((++sign_session_IV[(short)(i - 1)] != 0)){
                                        end = 1;
                                }
                        }
                        else{
                                dummy++;
                        }
                }
        }

	public boolean is_sign_session_opened(){
                if((wookeysig_state[0] == (byte)0xff) && (wookeysig_state[1] == (byte)0xff)){
	                return true;
                }
                return false;
	}

	public void close_sign_session(){
		/* Make this a transaction */
		JCSystem.beginTransaction();

		wookeysig_state[0] = (byte)0x00;
		wookeysig_state[1] = (byte)0x00;
		/* Zeroize the IV */
		Util.arrayFillNonAtomic(sign_session_IV, (short) 0, (short) sign_session_IV.length, (byte) 0);

		JCSystem.commitTransaction();
	}

	private void begin_sign_session(APDU apdu, byte ins){
	        /* The user asks for beginning a signature session, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x00);
                        return;
                }
		/* This instruction does not have data */
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
                if(data_len != 0){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x01);
			return;
		}
	        /* We check that we are already unlocked */
                if((W.pet_pin.isValidated() == false) || (W.user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x02);
                        return;
                }
		else{
			/* We return our singing session IV */
                        random.generateData(sign_session_IV, (short) 0, (short) sign_session_IV.length);
			Util.arrayCopyNonAtomic(sign_session_IV, (short) 0, W.data, (short) 0, (short) sign_session_IV.length);
			/* Compute the HMAC of signing session IV using our secret key */
			hmac_ctx.hmac_init(Keys.MasterSecretKey);
			hmac_ctx.hmac_update(sign_session_IV, (short) 0, (short) sign_session_IV.length);
			hmac_ctx.hmac_finalize(W.data, (short) sign_session_IV.length);
			short hmac_len = hmac_ctx.hmac_len();
			/* We are unlocked, update our local state */
			wookeysig_state[0] = (byte)0xff;
			wookeysig_state[1] = (byte)0xff;
			/* Initialize total number of chunk to 0 */
			num_chunks = 0;
			/* We return our session IV and its MAC as response data */
	                W.schannel.send_encrypted_apdu(apdu, W.data, (short) 0, (short) (sign_session_IV.length + hmac_len), (byte) 0x90, (byte) 0x00);
			return;
		}
	}

	private void sign_fimware_hash(APDU apdu, byte ins){
                /* The user asks for firmware signature, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x00);
                        return;
                }
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
		/* Check if a signing session is already opened */
		if(is_sign_session_opened() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x01);
                        return;
		}
		/* First, we close the signing session before performing the crypto part */
		close_sign_session();
                if(data_len != 32){
                        /* We should receive data in this command, and the size should be exactly 32 bytes (size of a SHA-256 hash) */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x02);
                        return;
                }
                /* We check that we are already unlocked */
                if((W.pet_pin.isValidated() == false) || (W.user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x03);
                        return;
                }
		else{
			short BN_len = (short) W.schannel.ec_context.p.length;
			/* We are authenticated. Proceed to the signature */
			W.schannel.ec_context.ecdsa_sign(W.data, (short) 0, data_len, W.data, (short) 0, W.schannel.working_buffer, SigPrivKey);
			/* Return the signature */
	        	W.schannel.send_encrypted_apdu(apdu, W.data, (short) 0, (short) (2 * BN_len), (byte) 0x90, (byte) 0x00);
			return;
		}
 	}

	private void verify_fimware_hash(APDU apdu, byte ins){
		short BN_len = (short) W.schannel.ec_context.p.length;
                /* The user asks for firmware verification, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x00);
                        return;
                }
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
                if(data_len != (short)(32 + (2 * BN_len))){
                        /* We should receive data in this command, and the size should be exactly 32 bytes (size of a hash) plus 2 big nums */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x01);
                        return;
                }
                /* We check that we are already unlocked */
                if((W.pet_pin.isValidated() == false) || (W.user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x02);
                        return;
                }
		else{
			/* We are authenticated. Proceed to the signature verification! */
			if(W.schannel.ec_context.ecdsa_verify(W.data, (short) 0, (short) 32, W.data, (short) 32, (short) (2 * BN_len), W.schannel.working_buffer, SigPubKey) == true){
				/* Return True */
				W.data[0] = (byte) 0x01;
			}
			else{
				/* Return False */
				W.data[0] = (byte) 0x00;
			}
	                W.schannel.send_encrypted_apdu(apdu, W.data, (short) 0, (short) 1, (byte) 0x90, (byte) 0x00);
			return;
		}
 	}

	private void derive_key(APDU apdu, byte ins){
                /* The user asks for key derivation, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x00);
                        return;
                }
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
		/* Check if a signing session is already opened */
		if(is_sign_session_opened() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x01);
                        return;
		}
                if(data_len != 0){
                        /* We should not receive data in this command */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x02);
                        return;
                }
                /* We check that we are already unlocked */
                if((W.pet_pin.isValidated() == false) || (W.user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x03);
                        return;
                }
		else{
			if(sign_session_IV == null){
                        	W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x04);
				return;
			}
			/* Check max chunks */
			if(num_chunks == MAX_NUM_CHUNKS){
				/* We have reached the maximum number of chunks allowed for the session */
				close_sign_session();
                        	W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x05);
				return;
			}
			/* Increment the number of chunks */
			num_chunks++;
			Util.arrayCopyNonAtomic(Keys.MasterSecretKey, (short) 0, W.schannel.working_buffer, (short) 0, (short) 16);
			Util.arrayCopyNonAtomic(Keys.MasterSecretKey, (short) 16, tmp, (short) 0, (short) 16);
			aes_ctx.aes_init(W.schannel.working_buffer, tmp, Aes.ENCRYPT);
			/* Encrypt the current IV */
			aes_ctx.aes(sign_session_IV, (short) 0, (short) sign_session_IV.length, W.data, (short) 0);
			/* Increment the current IV */
			next_iv();
			/* Return the derived key */
	                W.schannel.send_encrypted_apdu(apdu, W.data, (short) 0, (short) sign_session_IV.length, (byte) 0x90, (byte) 0x00);
			return;
		}
 	}

        private void get_sig_type(APDU apdu, byte ins){
                /* The user asks for the signature length, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x00);
                        return;
                }
                /* This instruction does not have data */
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
                if(data_len != 0){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x01);
                        return;
                }
                /* We check that we are already unlocked */
                if((W.pet_pin.isValidated() == false) || (W.user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x02);
                        return;
                }
                else{
                        /* We return our signature length on four bytes big endian + our signature libECC params on two bytes 
                         * Signature type (ECDSA, ...) + curve (FRP256V1, BRAINPOOL, ...)
                         */
                        W.data[0] = 0;
                        W.data[1] = 0;
                        W.data[2] = (byte)(W.schannel.ec_context.sigECDSAlen >> 8);
                        W.data[3] = (byte)W.schannel.ec_context.sigECDSAlen;
                        W.data[4] = Keys.LibECCparams[0];
                        W.data[5] = Keys.LibECCparams[1];
                        W.schannel.send_encrypted_apdu(apdu, W.data, (short) 0, (short) 6, (byte) 0x90, (byte) 0x00);
                        return;
                }
        }

	public void process(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();

		if (selectingApplet()){
			return;
		}

		if(W == null){
			/* Instantiate WooKey common class */
			W = new WooKey(Keys.UserPin, Keys.PetPin, Keys.OurPrivKeyBuf, Keys.OurPubKeyBuf, Keys.WooKeyPubKeyBuf, Keys.LibECCparams, Keys.PetName, Keys.PetNameLength, Keys.max_pin_tries, Keys.max_secure_channel_tries);
			/* Import the firmware signature keys once and for all */
			SigKeyPairWrapper = new ECKeyPair();
			W.schannel.ec_context.initialize_EC_key_pair_context(Keys.FirmwareSigPrivKeyBuf, false, Keys.FirmwareSigPubKeyBuf, SigKeyPairWrapper);
			/* Erase our now unnecessary buffers */
			Util.arrayFillNonAtomic(Keys.FirmwareSigPrivKeyBuf, (short) 0, (short) Keys.FirmwareSigPrivKeyBuf.length, (byte) 0);
			Util.arrayFillNonAtomic(Keys.FirmwareSigPubKeyBuf, (short) 0, (short) Keys.FirmwareSigPubKeyBuf.length, (byte) 0);
			SigKeyPair = SigKeyPairWrapper.kp;
			SigPrivKey = SigKeyPairWrapper.PrivKey;
			SigPubKey  = SigKeyPairWrapper.PubKey;
		}

		if(buffer[ISO7816.OFFSET_CLA] != (byte)0x00){
			ISOException.throwIt((short) 0x6660);
		}

                /* Begin to handle the common APDUs */
	        if(W.common_apdu_process(apdu) == true){
			return;
		}

		switch (buffer[ISO7816.OFFSET_INS])
		{
                        case (byte)TOKEN_INS_BEGIN_SIGN_SESSION:
	                        begin_sign_session(apdu, TOKEN_INS_BEGIN_SIGN_SESSION);
        	                return;
                        case (byte)TOKEN_INS_SIGN_FIRMWARE:
	                        sign_fimware_hash(apdu, TOKEN_INS_SIGN_FIRMWARE);
        	                return;
                        case (byte)TOKEN_INS_VERIFY_FIRMWARE:
	                        verify_fimware_hash(apdu, TOKEN_INS_VERIFY_FIRMWARE);
                                return;
	                case (byte)TOKEN_INS_DERIVE_KEY:
        	                derive_key(apdu, TOKEN_INS_DERIVE_KEY);
                	        return;
                        case (byte)TOKEN_INS_GET_SIG_TYPE:
	                        get_sig_type(apdu, TOKEN_INS_GET_SIG_TYPE);
        	                return;
			default:
                                /* Send unsupported APDU, in the secure channel or not depending if it has been initialized */
                                if(W.schannel.is_secure_channel_initialized() == true){
                                        short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
                                        /* Send unsupported APDU */
                                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) (ISO7816.SW_INS_NOT_SUPPORTED >> 8), (byte) ISO7816.SW_INS_NOT_SUPPORTED);
                                }
                                else{
                                        /* Send unsupported APDU */
                                        ISOException.throwIt((short) ISO7816.SW_INS_NOT_SUPPORTED);
                                }
		}
	}
}

