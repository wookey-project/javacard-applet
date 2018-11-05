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

        /* Counter to limit the global number of chunks in one session */
        private static short num_chunks = 0;
        final static short MAX_NUM_CHUNKS = (short)0xffff; 

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
                /* Our working temporary buffer */
                tmp = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);

 		new WooKeyDFU();
	}

	protected WooKeyDFU()
	{
		register();
	}

        /* Function that makes the chunk session IV evolve. We use a simple inrementation of the IV at each step. */
        private void next_iv(){
                short i;
                byte end = 0, dummy = 0;
                for(i = (short)dec_session_IV.length; i > 0; i--){
                        if(end == 0){
                                if((++dec_session_IV[(short)(i - 1)] != 0)){
                                        end = 1;
                                }
                        }
                        else{
                                dummy++;
                        }
                }
        }

        public void close_decrypt_session(){
                /* Make this a transaction */
                JCSystem.beginTransaction();

                wookeydec_state[0] = (byte)0x00;
                wookeydec_state[1] = (byte)0x00;
                /* Zeroize the IV */
                Util.arrayFillNonAtomic(dec_session_IV, (short) 0, (short) dec_session_IV.length, (byte) 0);

                JCSystem.commitTransaction();
        }


        public boolean is_decrypt_session_opened(){
                if((wookeydec_state[0] == (byte)0xff) && (wookeydec_state[1] == (byte)0xff)){
                        return true;
                }
                return false;
        }

	public void begin_decrypt_session(APDU apdu, byte ins){
                /* The user asks for beginning a decryption session, secure channel must be established */
                if(W.schannel.is_secure_channel_initialized() == false){
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x00);
                        return;
                }
                /* This instruction expects data: the initial IV and its HMAC, 16 bytes for the IV + 32 byte for the HMAC */
                short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
                if(data_len != (short)(dec_session_IV.length+hmac_ctx.hmac_len())){
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
			/* We extract our initial decryption IV */
                        Util.arrayCopyNonAtomic(W.data, (short) 0, dec_session_IV, (short) 0, (short) dec_session_IV.length);
			/* We compute its HMAC */
                	hmac_ctx.hmac_init(Keys.MasterSecretKey);
			hmac_ctx.hmac_update(dec_session_IV, (short) 0, (short) dec_session_IV.length);
			hmac_ctx.hmac_finalize(W.schannel.working_buffer, (short) 0);
			/* We compare the computed HMAC with the received one */
			if(Util.arrayCompare(W.schannel.working_buffer, (short) 0, W.data, (short) dec_session_IV.length, hmac_ctx.hmac_len()) != 0){
				/* HMAC is not OK, return an error */
                        	W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x03);
				return;
			}
                        /* HMAC is OK, open the session and return OK */
                        wookeydec_state[0] = (byte)0xff;
                        wookeydec_state[1] = (byte)0xff;
                        /* Initialize total number of chunk to 0 */
                        num_chunks = 0;
                        W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0x90, (byte) 0x00);
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
                /* Check if a decryption session is already opened */
                if(is_decrypt_session_opened() == false){
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
                        if(dec_session_IV == null){
                                W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x04);
                                return;
                        }
                        /* Check max chunks */
                        if(num_chunks == MAX_NUM_CHUNKS){
                                /* We have reached the maximum number of chunks allowed for the session */
                                close_decrypt_session();
                                W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) ins, (byte) 0x05);
                                return;
                        }
                        /* Increment the number of chunks */
                        num_chunks++;
                        Util.arrayCopyNonAtomic(Keys.MasterSecretKey, (short) 0, W.schannel.working_buffer, (short) 0, (short) 16);
                        Util.arrayCopyNonAtomic(Keys.MasterSecretKey, (short) 16, tmp, (short) 0, (short) 16);
                        aes_ctx.aes_init(W.schannel.working_buffer, tmp, Aes.ENCRYPT);
                        /* Encrypt the current IV */
                        aes_ctx.aes(dec_session_IV, (short) 0, (short) dec_session_IV.length, W.data, (short) 0);
                        /* Increment the current IV */
                        next_iv();
                        /* Return the derived key */
                        W.schannel.send_encrypted_apdu(apdu, W.data, (short) 0, (short) dec_session_IV.length, (byte) 0x90, (byte) 0x00);
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
                        case (byte)TOKEN_INS_BEGIN_DECRYPT_SESSION:
                                begin_decrypt_session(apdu, TOKEN_INS_BEGIN_DECRYPT_SESSION);
                                return;
                        case (byte)TOKEN_INS_DERIVE_KEY:
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
                                        ISOException.throwIt((short) ISO7816.SW_INS_NOT_SUPPORTED);
                                }
		}

	}
}

