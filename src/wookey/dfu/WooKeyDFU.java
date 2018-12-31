package wookey_dfu;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;

public class WooKeyDFU extends Applet implements ExtendedLength
{
	/* Our common WooKey class */
	private static WooKey W = null;

        /* Instructions specific to the DFU applet */
        public static final byte TOKEN_INS_BEGIN_DECRYPT_SESSION = (byte) 0x20;
        public static final byte TOKEN_INS_DERIVE_KEY = (byte) 0x21;

        /* The local state of the applet:
         * We expect the first APDU to come to be the one "opening" a
         * decryption session TOKEN_INS_BEGIN_DECRYPT_SESSION, then as many  
         * TOKEN_INS_DERIVE_KEY as necessary.
         */
        private static byte[] wookeydec_state = null;
        /* The session IV */
        private static byte[] dec_session_IV = null;
        private static byte[] cur_session_IV = null;

        /* Counter to limit the global number of chunks in one session */
        private static short[] last_num_chunk = null;
        private static short[] session_num_chunk = null;
        final static short MAX_NUM_CHUNKS = (short)0x7fff; 

	/* [RB] FIXME: we can handle the max number of derived session keys inside de card since
	 * we have the header with the encrypted content global length. However, this would require
	 * using 32 bites integers, which is not so straightforward using generic Javacard API.
	 */
	/* Save the current maximum number of chunks we get from the length */
	//private static short[] ; 

        /* HMAC contexts */
        private static Hmac hmac_ctx = null;
        /* AES context */
        private static Aes aes_ctx = null;
        /* Useful tmp buffer */
        private static byte[] tmp = null;


	public static void install(byte[] bArray,
                               short bOffset, byte bLength)
	{
                /* HMAC context */
                hmac_ctx = new Hmac(MessageDigest.ALG_SHA_256);
                /* AES context */
                aes_ctx = new Aes((short)16, Aes.CBC);
                /* The local variable handling our state */
                wookeydec_state = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
                wookeydec_state[0] = wookeydec_state[1] = 0;
                dec_session_IV = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
                cur_session_IV = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		last_num_chunk = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
		session_num_chunk = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
                /* Our working temporary buffer */
                tmp = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);

 		new WooKeyDFU();
	}

	protected WooKeyDFU()
	{
		register();
	}

        /* Self destroy the card */
        private void self_destroy_card(){
                /* We destroy all the assets */
                Util.arrayFillNonAtomic(Keys.MasterSecretKey, (short) 0, (short) Keys.MasterSecretKey.length, (byte) 0);
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
		Util.arrayCopyNonAtomic(dec_session_IV, (short) 0, cur_session_IV, (short) 0, (short) cur_session_IV.length);
		for(i = 0; i < num_chunk; i++){
			inc_iv();
		}
        }

        public void close_decrypt_session(){
                /* Make this a transaction */
                JCSystem.beginTransaction();

                wookeydec_state[0] = (byte)0x00;
                wookeydec_state[1] = (byte)0x00;
                /* Zeroize the IV */
                Util.arrayFillNonAtomic(dec_session_IV, (short) 0, (short) dec_session_IV.length, (byte) 0);
                Util.arrayFillNonAtomic(dec_session_IV, (short) 0, (short) cur_session_IV.length, (byte) 0);

                last_num_chunk[0] = 0;
		session_num_chunk[0] = 0;

                JCSystem.commitTransaction();
        }


        public boolean is_decrypt_session_opened(){
                if((wookeydec_state[0] == (byte)0xaa) && (wookeydec_state[1] == (byte)0x55)){
                        return true;
                }
                return false;
        }

	public void begin_decrypt_session(APDU apdu, byte ins){
                /* The user asks for beginning a decryption session, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x00);
                        return;
                }
		/* Close any previous decrypt session */
		close_decrypt_session();
                /* This instruction expects data: 
		 * Header = magic on 4 bytes || partition type on 4 bytes || version on 4 bytes || len of data after the header on 4 bytes || siglen on 4 bytes
		 * + MAX_CHUNK_SIZE(4 bytes) + IV + HMAC + SIG = (5*4) + 4 + 16 + 32 + 64
		 */
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
                if(data_len != (short)((5*4) + 4 + dec_session_IV.length + hmac_ctx.hmac_len() + ECCurves.get_EC_sig_len(Keys.LibECCparams))){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x01);
                        return;
                }
                /* We check that we are already unlocked */
                if((W.pet_pin.isValidated() == false) || (W.user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x02);
                        return;
                }
                else{
			/* We compute the HMAC on the received data except the HMAC itself */
                	hmac_ctx.hmac_init(Keys.MasterSecretKey);
			hmac_ctx.hmac_update(W.data, (short) 0, (short) (data_len - hmac_ctx.hmac_len() - ECCurves.get_EC_sig_len(Keys.LibECCparams)));
			hmac_ctx.hmac_update(W.data, (short) (data_len - ECCurves.get_EC_sig_len(Keys.LibECCparams)), ECCurves.get_EC_sig_len(Keys.LibECCparams));
			hmac_ctx.hmac_finalize(W.schannel.working_buffer, (short) 0);
			/* We compare the computed HMAC with the received one */
			if(Util.arrayCompare(W.schannel.working_buffer, (short) 0, W.data, (short) (data_len - hmac_ctx.hmac_len() - ECCurves.get_EC_sig_len(Keys.LibECCparams)), hmac_ctx.hmac_len()) != 0){
				/* HMAC is not OK, return an error */
                        	W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x03);
				return;
			}
                        /* HMAC is OK, open the session and return OK */
			/* We can extract our initial decryption IV */
                        Util.arrayCopyNonAtomic(W.data, (short) ((5*4) + 4), dec_session_IV, (short) 0, (short) dec_session_IV.length);
                        wookeydec_state[0] = (byte)0xaa;
                        wookeydec_state[1] = (byte)0x55;
                        /* Initialize last num chunk to 0 */
                        last_num_chunk[0] = 0;
			session_num_chunk[0] = 0;
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0x90, (byte) 0x00);
                        return;
                }
	}

        private void derive_key(APDU apdu, byte ins){
                /* The user asks for key derivation, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x00);
                        return;
                }
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
                /* Check if a decryption session is already opened */
                if(is_decrypt_session_opened() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x01);
                        return;
                }
                if(data_len != 2){
                        /* We should receive data in this command: 2 bytes representing the chunk number */
                        close_decrypt_session();
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x02);
                        return;
                }
                /* We check that we are already unlocked */
                if((W.pet_pin.isValidated() == false) || (W.user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        close_decrypt_session();
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x03);
                        return;
                }
                short chunk_num = (short)((W.data[0] << 8) ^ (W.data[1] & 0xff));
		if((chunk_num < 0) || (chunk_num > MAX_NUM_CHUNKS) || (session_num_chunk[0] > MAX_NUM_CHUNKS)){
                        close_decrypt_session();
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x04);
                        return;
		}
                else{
                        if((dec_session_IV == null) || (cur_session_IV == null)){
                        	close_decrypt_session();
                                W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x05);
                                return;
                        }
			session_num_chunk[0]++;
                        Util.arrayCopyNonAtomic(Keys.MasterSecretKey, (short) 0, W.schannel.working_buffer, (short) 0, (short) 16);
                        Util.arrayCopyNonAtomic(Keys.MasterSecretKey, (short) 16, tmp, (short) 0, (short) 16);
                        aes_ctx.aes_init(W.schannel.working_buffer, tmp, Aes.ENCRYPT);
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
                        aes_ctx.aes(cur_session_IV, (short) 0, (short) cur_session_IV.length, W.data, (short) 0);
                        /* Return the derived key */
                        W.schannel.send_encrypted_apdu(apdu, W.data, (short) 0, (short) dec_session_IV.length, (byte) 0x90, (byte) 0x00);
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
			close_decrypt_session();
			return;
		}

		if(W == null){
			W = new WooKey(Keys.UserPin, Keys.PetPin, Keys.OurPrivKeyBuf, Keys.OurPubKeyBuf, Keys.WooKeyPubKeyBuf, Keys.LibECCparams, Keys.PetName, Keys.PetNameLength, Keys.max_pin_tries, Keys.max_secure_channel_tries);
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
                        case TOKEN_INS_BEGIN_DECRYPT_SESSION:
                                begin_decrypt_session(apdu, TOKEN_INS_BEGIN_DECRYPT_SESSION);
                                return;
                        case TOKEN_INS_DERIVE_KEY:
                                derive_key(apdu, TOKEN_INS_DERIVE_KEY);
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
                                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                                }
		}

	}
}

