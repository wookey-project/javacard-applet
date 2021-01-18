package wookey_auth;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;

public class WooKeyAuth extends Applet implements ExtendedLength
{
	/* Our common WooKey class */
	private static WooKey W = null;

	/* Instructions specific to the AUTH applet */
	public static final byte TOKEN_INS_GET_KEY = (byte) 0x10;
	public static final byte TOKEN_INS_GET_SDPWD = (byte) 0x11;

	/* Variable handling initialization */
	private static byte init_done = 0x55;

	/* NOTE: we use our local enryption class for
	 * local protection of sensitive assets (the MSK in this case).
	 */
	EncLocalStorage local_msk_enc = null;

	public static void install(byte[] bArray,
                               short bOffset, byte bLength)
	{		
 		new WooKeyAuth();
	}

	protected WooKeyAuth()
	{
		register();
	}

        /* Self destroy the card */
        private void self_destroy_card(){
		local_msk_enc.destroy();
                Util.arrayFillNonAtomic(Keys.MasterSecretKey, (short) 0, (short) Keys.MasterSecretKey.length, (byte) 0);
		if(W != null){
			W.self_destroy_card();
		}
        }

	private void get_secret_data(APDU apdu, byte ins){
		/* The user asks to get the master key and its derivative, the secure channel must be initialized */
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
		if(data_len != 0){
			/* We should not receive data in this command */
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
			if(ins == TOKEN_INS_GET_KEY){
				/* Decrypt with local storage sensitive data, which is the ESSIV master key */
				local_msk_enc.Decrypt(Keys.MasterSecretKey, (short) 0, (short) 32, W.data, (short) 0);
				/* Also send SHA-256(ESSIV master key) */
				W.schannel.md.reset();
				W.schannel.md.doFinal(W.data, (short) 0, (short) 32, W.data, (short) 32);
				/* Now send the encrypted APDU */
				W.schannel.pin_encrypt_sensitive_data(W.data, W.data, (short) 0, (short) 64, (short) 64);
				W.schannel.send_encrypted_apdu(apdu, W.data, (short) 64, (short) 64, (byte) 0x90, (byte) 0x00);
				return;
			}
			else if(ins == TOKEN_INS_GET_SDPWD){
				/* Decrypt with local storage sensitive data, which is the ESSIV master key */
				local_msk_enc.Decrypt(Keys.SDPassword, (short) 0, (short) 16, W.data, (short) 0);
				/* Now send the encrypted APDU */
				W.schannel.pin_encrypt_sensitive_data(W.data, W.data, (short) 0, (short) 16, (short) 16);
				W.schannel.send_encrypted_apdu(apdu, W.data, (short) 16, (short) 16, (byte) 0x90, (byte) 0x00);
				return;
			}
			else{
				W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, WooKey.SW1_WARNING, (byte) 0x03);
				return;
			}
		}
		else{
			/* We are not authenticated, ask for an authentication */
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

			W = new WooKey(Keys.UserPin, Keys.PetPin, Keys.OurPrivKeyBuf, Keys.OurPubKeyBuf, Keys.WooKeyPubKeyBuf, Keys.LibECCparams, Keys.PetName, Keys.PetNameLength, Keys.max_pin_tries, Keys.max_secure_channel_tries, local_msk_enc);

			init_done = (byte) 0x55;
			
			/* Locally encrypt our MSK */
			local_msk_enc.Encrypt(Keys.MasterSecretKey, (short) 0, (short) Keys.MasterSecretKey.length, Keys.MasterSecretKey, (short) 0);	

			/* Locally encrypt our SD storage password */
			local_msk_enc.Encrypt(Keys.SDPassword, (short) 0, (short) Keys.SDPassword.length, Keys.SDPassword, (short) 0);	

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

		/* Now handle our specific APDUs */
		switch (buffer[ISO7816.OFFSET_INS])
		{
			case TOKEN_INS_GET_KEY:
				get_secret_data(apdu, TOKEN_INS_GET_KEY);
				return;
			case TOKEN_INS_GET_SDPWD:
				get_secret_data(apdu, TOKEN_INS_GET_SDPWD);
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
