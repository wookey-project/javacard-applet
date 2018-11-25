package wookey_auth;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;

public class WooKeyAuth extends Applet implements ExtendedLength
{
	/* Our common WooKey class */
	private static WooKey W = null;
	/* Private message digest context */
	private static MessageDigest md = null;

	/* Instructions specific to the AUTH applet */
	public static final byte TOKEN_INS_GET_KEY = (byte) 0x10;

	public static void install(byte[] bArray,
                               short bOffset, byte bLength)
	{
		md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
 		new WooKeyAuth();
	}

	protected WooKeyAuth()
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

	private void get_key(APDU apdu, byte ins){
		/* The user asks to get the master key and its derivative, the secure channel must be initialized */
		if(W.schannel.is_secure_channel_initialized() == false){
			W.schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x00);
			return;
		}
		short data_len = W.schannel.receive_encrypted_apdu(apdu, W.data);
		if(data_len != 0){
			/* We should not receive data in this command */
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
			/* Encrypt sensitive data, which is the ESSIV master key */
			Util.arrayCopyNonAtomic(Keys.MasterSecretKey, (short) 0, W.data, (short) 0, (short) 32);
			/* Also send SHA-256(ESSIV master key) */
			md.reset();
			md.doFinal(Keys.MasterSecretKey, (short) 0, (short) 32, W.data, (short) 32);
			W.schannel.pin_encrypt_sensitive_data(W.data, W.data, (short) 0, (short) 0, (short) 64);	
			/* Now send the encrypted APDU */
			W.schannel.send_encrypted_apdu(apdu, W.data, (short) 0, (short) 64, (byte) 0x90, (byte) 0x00);
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

		/* Now handle our specific APDUs */
		switch (buffer[ISO7816.OFFSET_INS])
		{
			case TOKEN_INS_GET_KEY:
				get_key(apdu, TOKEN_INS_GET_KEY);
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

