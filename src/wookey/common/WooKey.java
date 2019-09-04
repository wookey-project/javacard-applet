import javacard.framework.*;
import javacard.security.*;

public class WooKey
{
	/* NOTE: the debug mode activates echo tests for the secure channel.
	 * Should be removed in production.
	 */
	private static final boolean DEBUG_MODE = false;

	/* The secure channel instance */
	public SecureChannel schannel;
	/* PIN handling */
	public OwnerPIN pet_pin;
	public OwnerPIN user_pin;

        /* Temporary working buffer */
        public byte[] data = null;

        /* Failed secure channel attempts */
        private short sc_failed_attempts = 0;
	private short sc_max_failed_attempts;

	/* Class of instructions */
	public static final byte TOKEN_INS_SELECT_APPLET = (byte) 0xA4;
	public static final byte TOKEN_INS_SECURE_CHANNEL_INIT = (byte) 0x00;
	public static final byte TOKEN_INS_UNLOCK_PET_PIN = (byte) 0x01;
	public static final byte TOKEN_INS_UNLOCK_USER_PIN = (byte) 0x02;
	public static final byte TOKEN_INS_SET_USER_PIN = (byte) 0x03;
	public static final byte TOKEN_INS_SET_PET_PIN  = (byte) 0x04;
	public static final byte TOKEN_INS_SET_PET_NAME = (byte) 0x05;
	public static final byte TOKEN_INS_USER_PIN_LOCK = (byte) 0x06;
	public static final byte TOKEN_INS_FULL_LOCK = (byte) 0x07;
	public static final byte TOKEN_INS_GET_PET_NAME = (byte) 0x08;
	public static final byte TOKEN_INS_GET_RANDOM = (byte) 0x09;
	public static final byte TOKEN_INS_DERIVE_LOCAL_PET_KEY = (byte) 0x0a;
	/* FIXME: To be removed, for debug purpose only */
	public static final byte TOKEN_INS_ECHO_TEST = (byte) 0x0b;
	public static final byte TOKEN_INS_SECURE_CHANNEL_ECHO = (byte) 0x0c;
	/* Petname global value */
	private byte[] PetName = null;
        private short PetNameLength = 0;
	/* AES context to handle the local pet key */
	private Aes aes_ecb_ctx = null;
	/* Decrypted local pet key */
	private byte[] decrypted_local_pet_key = null;
	private byte[] tmp;

	/* Maximum PIN size */
	private final static byte MAX_PIN_SIZE = 32;

        /* Random data instance */
        private RandomData random = null;

	/* Variable handling the card lock state */
	public byte destroy_card = 0;

	/* Variable in eeprom handling the PetPin if the presentation has been performed OK (to limit brute force attacks) */
	private static final short max_pet_pin_derivation_failed_attempts = (short)32768;
	private short pet_pin_derivation_failed_attempts = 0;
	private byte dummy = 0;

	protected WooKey(byte[] UserPin, byte[] PetPin, byte[] OurPrivKeyBuf, byte[] OurPubKeyBuf, byte[] WooKeyPubKeyBuf, byte[] LibECCparams, byte[] petname, short petname_length, byte max_pin_fails, short max_sc_fails)
	{
		schannel = new SecureChannel(UserPin, OurPrivKeyBuf, OurPubKeyBuf, WooKeyPubKeyBuf, LibECCparams);
		initialize_pet_pin(PetPin, max_pin_fails, MAX_PIN_SIZE);
		initialize_user_pin(UserPin, max_pin_fails, MAX_PIN_SIZE);
		sc_max_failed_attempts = max_sc_fails;
		if(petname_length > petname.length){
			ISOException.throwIt((short) 0x1122);
		}
		PetName = petname;
		PetNameLength = petname_length;
		/* Erase all our sensitive buffers from flash now that we do not need them anymore ... */
		Util.arrayFillNonAtomic(PetPin, (short) 0, (short) PetPin.length, (byte) 0);
		Util.arrayFillNonAtomic(UserPin, (short) 0, (short) UserPin.length, (byte) 0);
		Util.arrayFillNonAtomic(OurPrivKeyBuf, (short) 0, (short) OurPrivKeyBuf.length, (byte) 0);
		Util.arrayFillNonAtomic(OurPubKeyBuf, (short) 0, (short) OurPubKeyBuf.length, (byte) 0);
		Util.arrayFillNonAtomic(WooKeyPubKeyBuf, (short) 0, (short) WooKeyPubKeyBuf.length, (byte) 0);
		/* Initialize the secure random source */
                random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		/* Initialize the aes context (AES-128 ECB) */
		aes_ecb_ctx = new Aes((short)16, Aes.ECB);
		initialize_ram();
	}

	void initialize_pet_pin(byte[] def_pin, byte trylimit, byte maxsize){
		pet_pin = new OwnerPIN(trylimit, maxsize);
		pet_pin.update(def_pin, (short) 0, (byte) def_pin.length);
	}

	void initialize_user_pin(byte[] def_pin, byte trylimit, byte maxsize){
		user_pin = new OwnerPIN(trylimit, maxsize);
		user_pin.update(def_pin, (short) 0, (byte) def_pin.length);
	}

	/* Function to initialize in RAM (transient) variables */
	void initialize_ram(){
                /* FIXME: we can release some pressure on the RAM side by reducing the size of this allocation to ~260.
                 * The > 260 bytes allocation is only here to support clear echo tests of extended APDUs, which is
                 * absolutely not used by our secure channel. It is only here for debug purposes!
                 */
                data = JCSystem.makeTransientByteArray((short) 280, JCSystem.CLEAR_ON_DESELECT);
		/* Decrypted local PET key. This is needed to be able to modify the PET pin */
		decrypted_local_pet_key = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
		tmp = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
	}

	/* Self destroy the card */
	public void self_destroy_card(){
		/* We destroy all the assets */
		destroy_card = (byte) 0xaa;
		Util.arrayFillNonAtomic(Keys.OurPrivKeyBuf, (short) 0, (short) Keys.OurPrivKeyBuf.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.EncLocalPetSecretKey, (short) 0, (short) Keys.EncLocalPetSecretKey.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.PetName, (short) 0, (short) Keys.PetName.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.PetPin, (short) 0, (short) Keys.PetPin.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.UserPin, (short) 0, (short) Keys.UserPin.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.OurPubKeyBuf, (short) 0, (short) Keys.OurPubKeyBuf.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.WooKeyPubKeyBuf, (short) 0, (short) Keys.WooKeyPubKeyBuf.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.LibECCparams, (short) 0, (short) Keys.LibECCparams.length, (byte) 0);
	}

	public void send_error(APDU apdu, byte[] err_data, short offset, short size, byte sw1, byte sw2){
                /* If we have such an error, we remove our secure channel */
		schannel.close_secure_channel();
                if(apdu.getCurrentState() != APDU.STATE_OUTGOING){
       	                apdu.setOutgoing();
               	}
		if(err_data != null){
	                apdu.setOutgoingLength(size);
        	        apdu.sendBytesLong(err_data, offset, size);
		}
                ISOException.throwIt((short) (((short)sw1 << 8) ^ (short)(sw2 & 0x00ff)));
	}

	// ECHO test outside the secure channel (FIXME: to be removed, for debug purposes)
	private void cleartext_echo_test(APDU apdu, byte ins){
		if(DEBUG_MODE == true){
			byte buffer[] = apdu.getBuffer();
			short bytesRead = apdu.setIncomingAndReceive();
	 		short echoOffset = (short)0;
			while ( bytesRead > 0 ) {
				Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, data, echoOffset, bytesRead);
				echoOffset += bytesRead;
				bytesRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        		}
		        apdu.setOutgoing();
        		apdu.setOutgoingLength( (short) (echoOffset + 5) );
        		// echo header
		        apdu.sendBytes( (short)0, (short) 5);
        		// echo data
	        	apdu.sendBytesLong( data, (short) 0, echoOffset );
			return;
		}
	}
	/* ECHO test in the secure channel (FIXME: to be removed, for debug purposes) */
	private void echo_test(APDU apdu, byte ins){
		if(DEBUG_MODE == true){
			if(schannel.is_secure_channel_initialized() == false){
				schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x00);
				return;
			}
			short outdata_len = schannel.receive_encrypted_apdu(apdu, data);
			schannel.send_encrypted_apdu(apdu, data, (short) 0, outdata_len, (byte) 0x90, (byte) 0x00);
			return;
		}
	}

	public void check_pin(APDU apdu, OwnerPIN pin, byte ins){
		short data_len = schannel.receive_encrypted_apdu(apdu, data);
		/* The user is sending his pin, the secure channel must be initialized */
		if(schannel.is_secure_channel_initialized() == false){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x00);
			return;
		}
		/* We cannot check the user pin before an authentication with the pet pin! */
		if((pin == user_pin) && (pet_pin.isValidated() == false)){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x01);
			return;
		}
		/* Get the real pin length (the PIN is padded to 16 bytes, the last byte represents the size) */
		if(data_len != 16){
			byte old_remaining = pin.getTriesRemaining();
			/* Bad length, decrement and respond an error */
			try {
				/* [RB] NOTE: The NullPointerException does not seem to decrement the pin count on the NXP JCOP ...
				 * contrary to what the Javacard API specification documents.
				 * Hence the check of old and new pin.getTriesRemaining().
				 */
				pin.check(null, (short) 0, (byte) 0);
			}
			catch(Exception e){
				/* We have forced a NullPointerException to decrement our counter */
			}
			/* Handle the case where the NullPointerException did not trigger an decrementation */
			byte new_remaining = pin.getTriesRemaining();
			if(old_remaining == new_remaining){
				/* Force the remaining tries decrementation by presenting a fake pin */
				pin.check(data, (short)0, (byte)0);
			}
			data[0] = pin.getTriesRemaining();
			schannel.send_encrypted_apdu(apdu, data, (short) 0, (short) 1, ins, (byte) 0x02);
			return;
		}
		short pin_len = (short)(data[15] & 0x00ff);
		/* Check pin real length */
		if((pin_len < 0) || (pin_len > 15)){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x03);
			return;
		}
		/* We have the pin, check it! */
		if(pin.check(data, (short) 0, (byte) pin_len) == false){
			/* Was this the last hope? */
			byte tries = pin.getTriesRemaining();
			if(tries == 0){
				/* Self destroy the card ...*/
				self_destroy_card();
				/* Card is blocked ... */
				data[0] = tries;
				schannel.send_encrypted_apdu(apdu, data, (short) 0, (short) 1, ins, (byte) 0x03);
				return;
			}
			else{
				/* Respond an error with the number of remaining tries */
				data[0] = tries;
				schannel.send_encrypted_apdu(apdu, data, (short) 0, (short) 1, ins, (byte) 0x04);
				return;
			}
		}
		else{
			/* PIN is OK: send that all is good, with the remaining pins as information */
			byte tmp = data[0]; 
			data[0] = pin.getTriesRemaining();
			schannel.send_encrypted_apdu(apdu, data, (short) 0, (short) 1, (byte) 0x90, (byte) 0x00);
			data[0] = tmp;
			schannel.adapt_keys(data);	
			return;
		}	
	}

	public void set_pin(APDU apdu, OwnerPIN pin, byte ins){
		short data_len = schannel.receive_encrypted_apdu(apdu, data);
		/* The user asks to change his pin, the secure channel must be initialized */
		if(schannel.is_secure_channel_initialized() == false){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x00);
			return;
		}
		/* We check that we are already unlocked (both pet pin and user pin presented) */
		if((pet_pin.isValidated() == false) || (user_pin.isValidated() == false)){
			/* We are not authenticated, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x01);
			return;
		}
		else{
			/* Try to change the pin */
			/* Get the real pin length (the PIN is padded to 16 bytes, the last byte represents the size) */
			if(pin == user_pin){
				if(data_len != 16){
					/* Bad length, respond an error */
					schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x02);
					return;
				}
			}
			if(pin == pet_pin){
				if(data_len != (16 + 64)){
					/* Bad length, respond an error */
					schannel.send_encrypted_apdu(apdu, data, (short) 0, (short) 0, ins, (byte) 0x02);
					return;
				}
			}
			short pin_len = (short)(data[15] & 0x00ff);

			/* Check new pin real length */
			if((pin_len < 4) || (pin_len > 15)){
				schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x03);
				return;
			}
			else{
				/* The following part is protected in a transaction to avoid tearing issues */
				JCSystem.beginTransaction();

				/* Update the PIN */
				pin.update(data, (short) 0, (byte) pin_len);
				/* Revalidate the PIN for future usage */
				if(pin.check(data, (short) 0, (byte) pin_len) == false){
					JCSystem.abortTransaction();
					schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x04);
					return;
				}
				/* In the case of the PET pin, we also have to re-encrypt our local pet key with the new pin */
				if(pin == pet_pin){
					/* Encrypt the local pet key master key and replace the old one */
					short i;
					for(i = 0; i < 4; i++){
						/* Chunk i */
						Util.arrayCopyNonAtomic(data, (short) ((short) 16 + (short) (i*16)), tmp, (short) 0, (short) 16);
						aes_ecb_ctx.aes_init(tmp, null, Aes.ENCRYPT);
						aes_ecb_ctx.aes(decrypted_local_pet_key, (short) (i*16), (short) 16, Keys.EncLocalPetSecretKey, (short) (i*16));
					}
				}

				if(pin == user_pin){
					schannel.update_pin_key(data, (byte) pin_len);
				}

				JCSystem.commitTransaction();
				
				/* Acknowledge and make the secure channel keys evolve witht the new pin */
				schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0x90, (byte) 0x00);
				schannel.adapt_keys(data);
			}	
		}

	}

	public void set_pet_name(APDU apdu, byte ins){
		short data_len = schannel.receive_encrypted_apdu(apdu, data);
		/* The user is sending the new pet name, the secure channel must be initialized */
		if(schannel.is_secure_channel_initialized() == false){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x00);
			return;
		}
		/* We check that we are already unlocked (both pet pin and user pin presented) */
		if((pet_pin.isValidated() == false) || (user_pin.isValidated() == false)){
			/* We are not authenticated, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x01);
			return;
		}
		else{
			/* Check maximum length for our pet name sentence ... */
			if(data_len > PetName.length){
				data[0] = (byte)data_len;
				data[1] = (byte)PetName.length;
				schannel.send_encrypted_apdu(apdu, data, (short) 0, (short) 2, ins, (byte) 0x02);
				return;
			}
			/* Modify the PET name */
			Util.arrayFillNonAtomic(PetName, (short) 0, (short) PetName.length, (byte) 0);
			Util.arrayCopyNonAtomic(data, (short) 0, PetName, (short) 0, data_len);
			PetNameLength = data_len;
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0x90, (byte) 0x00);
			return;
		}
	}

	public void user_pin_lock_token(APDU apdu, byte ins){
		short data_len = schannel.receive_encrypted_apdu(apdu, data);
		/* The user asks to lock the token, the secure channel must be initialized */
		if(schannel.is_secure_channel_initialized() == false){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x00);
			return;
		}
		if(data_len != 0){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x01);
			return;
		}
		/* If the session is not unlocked, we have nothing to do, else we lock it */
		if(user_pin.isValidated() == true){
			/* Note: we reset the pin. The side effect is a try counter reset, bu this is OK
			 * since an unlocked session means a reset of the counters anyways.
			 */
			user_pin.reset();
		}
		schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0x90, (byte) 0x00);
		return;
	}

	public void full_lock_token(APDU apdu, byte ins){
		short data_len = schannel.receive_encrypted_apdu(apdu, data);
		/* The user asks to fully lock the token, the secure channel must be initialized */
		if(schannel.is_secure_channel_initialized() == false){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x00);
			return;
		}
		if(data_len != 0){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x01);
			return;
		}
		/* If the session is not unlocked, we have nothing to do, else we lock it */
		if(user_pin.isValidated() == true){
			/* Note: we reset the pin. The side effect is a try counter reset, bu this is OK
			 * since an unlocked session means a reset of the counters anyways.
			 */
			user_pin.reset();
		}
		if(pet_pin.isValidated() == true){
			/* Note: we reset the pin. The side effect is a try counter reset, bu this is OK
			 * since an unlocked session means a reset of the counters anyways.
			 */
			pet_pin.reset();
		}
		/* Respond OK */
		schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0x90, (byte) 0x00);
		/* Kill the secure channel */
		schannel.close_secure_channel();
	}

	private void get_pet_name(APDU apdu, byte ins){
		short data_len = schannel.receive_encrypted_apdu(apdu, data);
		if(schannel.is_secure_channel_initialized() == false){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x00);
			return;
		}
		if(data_len != 0){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x01);
			return;
		}
		if(pet_pin.isValidated() == false){
			/* We are not authenticated with the PET PIN, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x02);
			return;
		}
		else{
			/* We send the pet name through the secure channel */
			schannel.send_encrypted_apdu(apdu, PetName, (short) 0, PetNameLength, (byte) 0x90, (byte) 0x00);
			return;
		}
	}

	/* Common service to provide secure random from the smartcard to the host */
	private void get_random(APDU apdu, byte ins){
		/* Asking for random needs a secure channel established as well as a user authentication */
                if(schannel.is_secure_channel_initialized() == false){
                        schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x00);
                        return;
                }
                short data_len = schannel.receive_encrypted_apdu(apdu, data);
                if(data_len != 1){
                        schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x01);
                        return;
                }
                /* We check that we are already unlocked (pet and user pin) */
                if((pet_pin.isValidated() == false) || (user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x02);
                        return;
                }
                else{
                	/* This instruction expects a byte containing the size of random data to provide (maximum 256 bytes minus a HMAC size) */
			short rand_len = (short)(data[0] & 0x00ff);
			if(rand_len > schannel.get_max_sc_apdu_send_len()){
        	                schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x03);
                	        return;
			}
			try {
				random.generateData(data, (short) 0, rand_len);
			}
			catch(CryptoException exception){
                        	schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x04);
				return;
			}
                        schannel.send_encrypted_apdu(apdu, data, (short) 0, rand_len, (byte) 0x90, (byte) 0x00);
			return;
		}
	}

	/* Sleep a time in square of to the asked input */
	private void sleep(short to_sleep){
		short i, j;
		for(j = 0; j < to_sleep; j++){
			for(i = 0; i < to_sleep; i++){
				/* Increment a dummy value in EEPROM to avoid optimisation */
				dummy++;
			}
		}
	}

	/* Derive the local pet key to send it to the platform */
	private void derive_local_pet_key(APDU apdu, byte ins){
		/* This command is the only one that does not need a secure channel initialization ...
		 * (except for the select applet and secure channel negotiation ones of course)
		 * since the platform needs to decrypt its keys using this derivation *before* mounting
		 * the secure channel!
		 */
		/* Security against brute force */
		if(pet_pin_derivation_failed_attempts == max_pet_pin_derivation_failed_attempts){
				/* Self destroy the card ...*/
				self_destroy_card();
		}
	        if(schannel.is_secure_channel_initialized() == true){
                        schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, ins, (byte) 0x00);
                        return;
                }
		/* This instruction expects 64 bytes of data (the PBKDF2 generated from the PET PIN) */
		short receivedLen = apdu.setIncomingAndReceive();
		if(receivedLen != 64){
			ISOException.throwIt((short) 0xBBAA);
		}
		byte buffer[] = apdu.getBuffer();
                short OffsetCdata = apdu.getOffsetCdata();
		/* Security against brute force: preincrement the value, it will be reset to 0
		 * when the secure channel is mounted (ensuring that the Pet PIN has been properly
		 * provided.
		 * We also sleep a time in square of the number of failed attempts.
		 */
		sleep(pet_pin_derivation_failed_attempts);
		pet_pin_derivation_failed_attempts++;
		/* Decrypt the master key and send it */
		short i;
		for(i = 0; i < 4; i++){
			/* Chunk i */
			Util.arrayCopyNonAtomic(buffer, (short) ((short) ISO7816.OFFSET_CDATA + (short) (i*16)), tmp, (short) 0, (short) 16);
			aes_ecb_ctx.aes_init(tmp, null, Aes.DECRYPT);
			aes_ecb_ctx.aes(Keys.EncLocalPetSecretKey, (short) (i*16), (short) 16, decrypted_local_pet_key, (short) (i*16));
		}
		/* Send the decrypted local pet key */
	        apdu.setOutgoing();
        	apdu.setOutgoingLength( (short) (decrypted_local_pet_key.length));
	        apdu.sendBytesLong(decrypted_local_pet_key, (short) 0, (short) decrypted_local_pet_key.length);

		return;
	}

	public void secure_channel_init(APDU apdu, byte ins){
		if(sc_failed_attempts >= sc_max_failed_attempts){
			/* Self destroy the card ...*/
			self_destroy_card();
			send_error(apdu, null, (short) 0, (short) 0, ins, (byte) 0x01);
			return;
		}
		try{
			/* Preincrement the failed attemps to limit tearing/fault attacks */
			sc_failed_attempts++;
			schannel.secure_channel_init(apdu, data);
		}
		catch(Exception e){
			data[0] = (byte) ((short)(sc_max_failed_attempts - sc_failed_attempts) >>> 8);
			data[1] = (byte) ((sc_max_failed_attempts - sc_failed_attempts) & 0xff);
			send_error(apdu, data, (short) 0, (short) 2, ins, (byte) 0x00);
			return;
		}
		/* Reset the failed_attempts counter if we have successfully established a channel */
		sc_failed_attempts = 0;
		/* Reset the counter handling brute force limitation (the Pet PIN was OK since we have
		 * mounted the secure channel).
		 */
		pet_pin_derivation_failed_attempts = 0;
	}

	public boolean common_apdu_process(APDU apdu)
	{
		/* Check the card status */
		if(destroy_card != 0){
			self_destroy_card();
			ISOException.throwIt((short) 0xDEAD);
		}

		byte[] buffer = apdu.getBuffer();
		
		switch (buffer[ISO7816.OFFSET_INS])
		{
			case TOKEN_INS_ECHO_TEST:
				if(DEBUG_MODE == true){
					cleartext_echo_test(apdu, TOKEN_INS_ECHO_TEST);
					return true;
				}
				return false;
			case TOKEN_INS_SECURE_CHANNEL_INIT:
				secure_channel_init(apdu, TOKEN_INS_SECURE_CHANNEL_INIT);
				return true;
			case TOKEN_INS_SECURE_CHANNEL_ECHO:
				if(DEBUG_MODE == true){
					echo_test(apdu, TOKEN_INS_SECURE_CHANNEL_ECHO);
					return true;
				}
				return false;
			case TOKEN_INS_UNLOCK_PET_PIN:
				/* Check pet PIN */
				check_pin(apdu, pet_pin, TOKEN_INS_UNLOCK_PET_PIN);
				return true;
			case TOKEN_INS_UNLOCK_USER_PIN:
				/* Check user PIN */
				check_pin(apdu, user_pin, TOKEN_INS_UNLOCK_USER_PIN);
				return true;
			case TOKEN_INS_SET_USER_PIN:
				/* Set user PIN */
				set_pin(apdu, user_pin, TOKEN_INS_SET_USER_PIN);
				return true;
			case TOKEN_INS_SET_PET_PIN:
				/* Set PET PIN */
				set_pin(apdu, pet_pin, TOKEN_INS_SET_PET_PIN);
				return true;
			case TOKEN_INS_SET_PET_NAME:
				/* Set user PIN */
				set_pet_name(apdu, TOKEN_INS_SET_PET_NAME);
				return true;
			case TOKEN_INS_USER_PIN_LOCK:
				user_pin_lock_token(apdu, TOKEN_INS_USER_PIN_LOCK);
				return true;
			case TOKEN_INS_FULL_LOCK:
				full_lock_token(apdu, TOKEN_INS_FULL_LOCK);
				return true;
			case TOKEN_INS_GET_PET_NAME:
				get_pet_name(apdu, TOKEN_INS_GET_PET_NAME);
				return true;
			case TOKEN_INS_GET_RANDOM:
				get_random(apdu, TOKEN_INS_GET_RANDOM);
				return true;
			case TOKEN_INS_DERIVE_LOCAL_PET_KEY:
				derive_local_pet_key(apdu, TOKEN_INS_DERIVE_LOCAL_PET_KEY);
				return true;
			default:
				return false;
		}

	}
}

