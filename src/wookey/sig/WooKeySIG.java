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
        /* NOTE: we reuse crypto contexts from the secure channel layer. This is done to **save memory**. */
	/* Useful tmp buffer */
	private static byte[] tmp = null;

        /* [RB] FIXME/TODO: we can handle the max number of derived session keys inside de card since
         * we have the header with the encrypted content global length. However, this would require
         * using 32-bit integers, which is not so straightforward using generic Javacard API.
         */
	/* Counter to limit the global number of chunks in one session */
        private static short[] last_num_chunk = null;
        private static short[] session_num_chunk = null;
	final static short MAX_NUM_CHUNKS = (short)0x7fff;

	/* The local state of the applet:
	 * We expect the first APDU to come to be the one "opening" a
         * signing session TOKEN_INS_BEGIN_SIGN_SESSION, then as many  
	 * TOKEN_INS_DERIVE_KEY as necessary, then (and only then) a
	 * TOKEN_INS_SIGN_FIRMWARE closing the session.
	 */
	private static byte[] wookeysig_state = null;
	/* The session IV */
	private static byte[] sign_session_IV = null;
	private static byte[] cur_session_IV = null;
	
        /* Instructions specific to the SIG applet */
        public static final byte TOKEN_INS_BEGIN_SIGN_SESSION = (byte) 0x30;
        public static final byte TOKEN_INS_DERIVE_KEY = (byte) 0x31;
        public static final byte TOKEN_INS_SIGN_FIRMWARE = (byte) 0x32;
        public static final byte TOKEN_INS_VERIFY_FIRMWARE = (byte) 0x33;
        public static final byte TOKEN_INS_GET_SIG_TYPE = (byte) 0x34;

        /* Variable handling initialization */
        private static byte init_done = (byte)0x55;

        /* NOTE: we use our local enryption class for
         * local protection of sensitive assets (the MSK in this case).
         */
        EncLocalStorage local_msk_enc = null;

	public static void install(byte[] bArray,
                               short bOffset, byte bLength)
	{
		/* The local variable handling our state */
		wookeysig_state = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
		wookeysig_state[0] = wookeysig_state[1] = 0;
		sign_session_IV = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		cur_session_IV = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
                last_num_chunk = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
                session_num_chunk = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
		/* Random instance */
		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		/* Our working temporary buffer */
		tmp = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);

 		new WooKeySIG();
	}

	protected WooKeySIG()
	{
		register();
	}

        /* Self destroy the card */
        private void self_destroy_card(){
                /* We destroy all the assets */
                local_msk_enc.destroy();
                Util.arrayFillNonAtomic(Keys.MasterSecretKey, (short) 0, (short) Keys.MasterSecretKey.length, (byte) 0);
                Util.arrayFillNonAtomic(Keys.FirmwareSigPrivKeyBuf, (short) 0, (short) Keys.FirmwareSigPrivKeyBuf.length, (byte) 0);
                Util.arrayFillNonAtomic(Keys.FirmwareSigPubKeyBuf, (short) 0, (short) Keys.FirmwareSigPubKeyBuf.length, (byte) 0);
                if(W != null){
                        W.self_destroy_card();
                }
        }

        /* Function that makes the chunk session IV evolve. We use a simple inrementation of the IV at each step. */
        private void inc_iv(){
                short i;
                byte end = 0, dummy = 0;
                for(i = (short)cur_session_IV.length; i > 0; i--){
                        if(end == 0){
                                if((++cur_session_IV[(short)(i - 1)] != 0)){
                                        end = 1;
                                }
                        }
                        else{
                                dummy++;
                        }
                }
        }
        private void compute_iv(short num_chunk){
                short i;
                Util.arrayCopyNonAtomic(sign_session_IV, (short) 0, cur_session_IV, (short) 0, (short) cur_session_IV.length);
                for(i = 0; i < num_chunk; i++){
                        inc_iv();
                }
        }

        public boolean is_sign_session_opened(){
                if(wookeysig_state[0] == (byte)0xaa){
                        if(wookeysig_state[1] == (byte)0x55){
                                return true;
                        }
                        else{
                                return false;
                        }
                }
                else{
                        return false;
                }
        }

	public void close_sign_session(){
		/* Make this a transaction */
		JCSystem.beginTransaction();

		wookeysig_state[0] = (byte)0x00;
		wookeysig_state[1] = (byte)0x00;
		/* Zeroize the IV */
		Util.arrayFillNonAtomic(sign_session_IV, (short) 0, (short) sign_session_IV.length, (byte) 0);

		last_num_chunk[0] = 0;
                session_num_chunk[0] = 0;

		JCSystem.commitTransaction();
	}

	private void begin_sign_session(APDU apdu, byte ins){
	        /* The user asks for beginning a signature session, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
                if(W.sc_checkpoint[0] != (byte)0xaa){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
                if(W.sc_checkpoint[1] != (byte)0x55){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
		/* First, we close any previous signing session ... */
		close_sign_session();
                /* This instruction expects data: 
                 * Header = magic on 4 bytes ||partition type on 4 bytes ||version on 4 bytes || len of data after the header on 4 bytes ||siglen on 4 bytes
                 * + MAX_CHUNK_SIZE(4 bytes) + SIG = (5*4) + 4 + 64
                 */
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
                if(data_len != (short)((5*4) + 4 + ECCurves.get_EC_sig_len(Keys.LibECCparams))){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x01);
			return;
		}
	        /* We check that we are already unlocked */
                if((W.pet_pin.isValidated() == false) || (W.user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
                }
                /* Double check against faults */
                if(W.pet_pin.isValidated() == true){
                        if(W.user_pin.isValidated() == true){
                        }
                }
                else{
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
		}
                if((W.pet_pin.isValidated() == true) && (W.user_pin.isValidated() == true)){
			/* We generate our signing session IV */
                        random.generateData(sign_session_IV, (short) 0, (short) sign_session_IV.length);
			/* Compute the HMAC of the data using our secret key */
                        local_msk_enc.Decrypt(Keys.MasterSecretKey, (short) 0, (short) 32, tmp, (short) 0);
			W.schannel.hmac_ctx.hmac_init(tmp, (short) 0, (short) 32);
			W.schannel.hmac_ctx.hmac_update(W.data, (short) 0, (short) (data_len - ECCurves.get_EC_sig_len(Keys.LibECCparams)));
			W.schannel.hmac_ctx.hmac_update(sign_session_IV, (short) 0, (short) sign_session_IV.length);
			W.schannel.hmac_ctx.hmac_update(W.data, (short) (data_len - ECCurves.get_EC_sig_len(Keys.LibECCparams)), ECCurves.get_EC_sig_len(Keys.LibECCparams));
			W.schannel.hmac_ctx.hmac_finalize(W.data, (short) sign_session_IV.length);
			Util.arrayCopyNonAtomic(sign_session_IV, (short) 0, W.data, (short) 0, (short) sign_session_IV.length);
			Util.arrayCopyNonAtomic(sign_session_IV, (short) 0, cur_session_IV, (short) 0, (short) cur_session_IV.length);
			short hmac_len = W.schannel.hmac_ctx.hmac_len();
			/* We are unlocked, update our local state */
			wookeysig_state[0] = (byte)0xaa;
			wookeysig_state[1] = (byte)0x55;
                        /* Initialize last num chunk to 0 */
                        last_num_chunk[0] = 0;
			session_num_chunk[0] = 0;
			/* We return our session IV and the MAC as response data */
	                W.schannel.send_encrypted_apdu(apdu, W.data, (short) 0, (short) (sign_session_IV.length + hmac_len), (byte) 0x90, (byte) 0x00);
			return;
		}
		else{
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
		}
	}

	private void sign_fimware_hash(APDU apdu, byte ins){
                /* The user asks for firmware signature, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
                if(W.sc_checkpoint[0] != (byte)0xaa){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
                if(W.sc_checkpoint[1] != (byte)0x55){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
		/* First, we close any previous signing session since signing is the first action one should perform ... */
		close_sign_session();
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
                if(data_len != 32){
                        /* We should receive data in this command, and the size should be exactly 32 bytes (size of a SHA-256 hash) */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x01);
                        return;
                }
                /* We check that we are already unlocked */
                if((W.pet_pin.isValidated() == false) || (W.user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
                }
                /* Double check against faults */
                if(W.pet_pin.isValidated() == true){
                        if(W.user_pin.isValidated() == true){
                        }
                }
                else{
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
		}
                if((W.pet_pin.isValidated() == true) && (W.user_pin.isValidated() == true)){
			short BN_len = (short) W.schannel.ec_context.p.length;
			/* We are authenticated. Proceed to the signature */
			W.schannel.ec_context.ecdsa_sign(W.data, (short) 0, data_len, W.data, (short) 0, W.schannel.working_buffer, SigPrivKey);
			/* Return the signature */
	        	W.schannel.send_encrypted_apdu(apdu, W.data, (short) 0, (short) (2 * BN_len), (byte) 0x90, (byte) 0x00);
			return;
		}
		else{
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
		}
 	}

	private void verify_fimware_hash(APDU apdu, byte ins){
                /* The user asks for firmware verification, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
                if(W.sc_checkpoint[0] != (byte)0xaa){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
                if(W.sc_checkpoint[1] != (byte)0x55){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
		short BN_len = (short) W.schannel.ec_context.p.length;
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
                if(data_len != (short)(32 + (2 * BN_len))){
                        /* We should receive data in this command, and the size should be exactly 32 bytes (size of a hash) plus 2 big nums */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x01);
                        return;
                }
                /* We check that we are already unlocked */
                if((W.pet_pin.isValidated() == false) || (W.user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
                }
                /* Double check against faults */
                if(W.pet_pin.isValidated() == true){
                        if(W.user_pin.isValidated() == true){
                        }
                }
                else{
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
		}
                if((W.pet_pin.isValidated() == true) && (W.user_pin.isValidated() == true)){
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
		else{
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
		}
 	}

	private void derive_key(APDU apdu, byte ins){
                /* The user asks for key derivation, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
                if(W.sc_checkpoint[0] != (byte)0xaa){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
                if(W.sc_checkpoint[1] != (byte)0x55){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
		/* Check if a signing session is already opened */
		if(is_sign_session_opened() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x01);
                        return;
		}
		/* Double check against faults */
		if(is_sign_session_opened() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x01);
                        return;
		}
                if(data_len != 2){
                        /* We should receive data in this command: 2 bytes representing the chunk number */
			close_sign_session();
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
                }
                /* We check that we are already unlocked */
                if((W.pet_pin.isValidated() == false) || (W.user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
			close_sign_session();
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x03);
                        return;
                }
                /* Double check against faults */
                if(W.pet_pin.isValidated() == true){
                        if(W.user_pin.isValidated() == true){
                        }
                }
                else{
                        /* We are not authenticated, ask for an authentication */
			close_sign_session();
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x03);
                        return;
		}
                if((W.pet_pin.isValidated() == true) && (W.user_pin.isValidated() == true)){
	                short chunk_num = (short)((W.data[0] << 8) ^ (W.data[1] & 0xff));
        	        if((chunk_num < 0) || (chunk_num > MAX_NUM_CHUNKS) || (session_num_chunk[0] > MAX_NUM_CHUNKS)){
				close_sign_session();
                        	W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x04);
	                        return;
        	        }
			else{
				if((sign_session_IV == null) || (cur_session_IV == null)){
					close_sign_session();
	                        	W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x05);
					return;
				}
				session_num_chunk[0]++;
	                        /* Decrypt our derivation key and IV from the local storage backend */
	                        local_msk_enc.Decrypt(Keys.MasterSecretKey, (short) 32, (short) 16, W.schannel.working_buffer, (short) 0);
        	                local_msk_enc.Decrypt(Keys.MasterSecretKey, (short) 48, (short) 16, tmp, (short) 0);
				W.schannel.aes_cbc_ctx.aes_init(W.schannel.working_buffer, tmp, Aes.ENCRYPT);
       	                	/* Compute current session key */
	                        if(chunk_num >= last_num_chunk[0]){
        	                        short i;
                	                for(i = 0; i < (short)(chunk_num-last_num_chunk[0]); i++){
                        	                inc_iv();
                                	}
	                        }
        	                else{
                	                compute_iv(chunk_num);
	                        }
                        	last_num_chunk[0] = chunk_num;
				/* Encrypt the current IV */
				W.schannel.aes_cbc_ctx.aes(cur_session_IV, (short) 0, (short) cur_session_IV.length, W.data, (short) 0);
				/* Return the derived key */
	                	W.schannel.send_encrypted_apdu(apdu, W.data, (short) 0, (short) sign_session_IV.length, (byte) 0x90, (byte) 0x00);
				return;
			}
		}
		else{
                        /* We are not authenticated, ask for an authentication */
			close_sign_session();
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x03);
                        return;
		}
 	}

        private void get_sig_type(APDU apdu, byte ins){
                /* The user asks for the signature length, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
                if(W.sc_checkpoint[0] != (byte)0xaa){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
                if(W.sc_checkpoint[1] != (byte)0x55){
                        W.send_error(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x00);
                        return;
                }
                /* This instruction does not have data */
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
                if(data_len != 0){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x01);
                        return;
                }
                /* We check that we are already unlocked */
                if((W.pet_pin.isValidated() == false) || (W.user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
                }
                /* Double check against faults */
                if(W.pet_pin.isValidated() == true){
                        if(W.user_pin.isValidated() == true){
                        }
                }
                else{
                        /* We are not authenticated, ask for an authentication */
			close_sign_session();
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
		}
                if((W.pet_pin.isValidated() == true) && (W.user_pin.isValidated() == true)){
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
		else{
                        /* We are not authenticated, ask for an authentication */
			close_sign_session();
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x02);
                        return;
		}
        }

	public void process(APDU apdu)
	{
                /* Self destroy? */
                if(W != null){
                        if(W.destroy_card != 0){
                                self_destroy_card();
                        }
                }

		byte[] buffer = apdu.getBuffer();

		if (selectingApplet()){
			/* Reinitialize */
			close_sign_session();
			return;
		}
                if(init_done == (byte) 0x55){
                        if(W != null){
                                /* This should not happen */
                                W.destroy_card = (byte) 0xaa;
                                ISOException.throwIt((short) 0x6660);
                        }
                        /* Proceed with initialization */
                        init_done = (byte) 0x55;

                        /* Instantiate our local storage class to protect sensitive assets */
                        local_msk_enc = new EncLocalStorage();

			/* Instantiate WooKey common class */
			W = new WooKey(Keys.UserPin, Keys.PetPin, Keys.OurPrivKeyBuf, Keys.OurPubKeyBuf, Keys.WooKeyPubKeyBuf, Keys.LibECCparams, Keys.PetName, Keys.PetNameLength, Keys.max_pin_tries, Keys.max_secure_channel_tries, local_msk_enc);

                        init_done = (byte) 0x55;

			/* Import the firmware signature keys once and for all */
			SigKeyPairWrapper = new ECKeyPair();
			W.schannel.ec_context.initialize_EC_key_pair_context(Keys.FirmwareSigPrivKeyBuf, false, Keys.FirmwareSigPubKeyBuf, SigKeyPairWrapper);
			/* Erase our now unnecessary buffers */
			Util.arrayFillNonAtomic(Keys.FirmwareSigPrivKeyBuf, (short) 0, (short) Keys.FirmwareSigPrivKeyBuf.length, (byte) 0);
			Util.arrayFillNonAtomic(Keys.FirmwareSigPubKeyBuf, (short) 0, (short) Keys.FirmwareSigPubKeyBuf.length, (byte) 0);
			SigKeyPair = SigKeyPairWrapper.kp;
			SigPrivKey = SigKeyPairWrapper.PrivKey;
			SigPubKey  = SigKeyPairWrapper.PubKey;

                        init_done = (byte) 0x55;

                        /* Locally encrypt our MSK */
                        local_msk_enc.Encrypt(Keys.MasterSecretKey, (short) 0, (short) Keys.MasterSecretKey.length, Keys.MasterSecretKey, (short) 0);
			
                        init_done = (byte) 0xaa;
		}

                if(init_done != (byte) 0xaa){
                        ISOException.throwIt((short) 0x6660);
                }

		if(buffer[ISO7816.OFFSET_CLA] != (byte)0x00){
			ISOException.throwIt((short) 0x6661);
		}

                /* Begin to handle the common APDUs */
	        if(W.common_apdu_process(apdu) == true){
			return;
		}

		switch (buffer[ISO7816.OFFSET_INS])
		{
                        case TOKEN_INS_BEGIN_SIGN_SESSION:
	                        begin_sign_session(apdu, TOKEN_INS_BEGIN_SIGN_SESSION);
        	                return;
                        case TOKEN_INS_SIGN_FIRMWARE:
	                        sign_fimware_hash(apdu, TOKEN_INS_SIGN_FIRMWARE);
        	                return;
                        case TOKEN_INS_VERIFY_FIRMWARE:
	                        verify_fimware_hash(apdu, TOKEN_INS_VERIFY_FIRMWARE);
                                return;
	                case TOKEN_INS_DERIVE_KEY:
        	                derive_key(apdu, TOKEN_INS_DERIVE_KEY);
                	        return;
                        case TOKEN_INS_GET_SIG_TYPE:
	                        get_sig_type(apdu, TOKEN_INS_GET_SIG_TYPE);
        	                return;
			default:
                                /* Send unsupported APDU, in the secure channel or not depending if it has been initialized */
                                if(W.schannel.is_secure_channel_initialized() == true){
                                        short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
                                        /* Send unsupported APDU */
                                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) (ISO7816.SW_INS_NOT_SUPPORTED >> 8), (byte) ISO7816.SW_INS_NOT_SUPPORTED);
					return;
                                }
                                else{
                                        /* Send unsupported APDU */
                                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                                }
		}
	}
}

