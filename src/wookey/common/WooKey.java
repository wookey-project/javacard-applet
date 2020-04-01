import javacard.framework.*;
import javacard.security.*;

public class WooKey
{
	/* NOTE: the debug mode activates echo tests for the secure channel.
	 * Should be removed in production.
	 */
	private static final boolean DEBUG_MODE = true;

	public static final byte SW1_WARNING = 0x63;

	/* The secure channel instance
	 * NOTE: it is public so that crypto instances in the Secure Channel
	 * layer can be reused by other classes to *save memory*
 	 */
	public SecureChannel schannel = null;
	/* PIN handling */
	public OwnerPIN pet_pin = null;
	public OwnerPIN user_pin = null;

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
	public static final byte TOKEN_INS_GET_CHALLENGE = (byte) 0x0b;
	/* FIXME: To be removed, for debug purpose only */
	public static final byte TOKEN_INS_ECHO_TEST = (byte) 0x0c;
	public static final byte TOKEN_INS_SECURE_CHANNEL_ECHO = (byte) 0x0d;
	/* Petname global value */
	private byte[] PetName = null;
        private short PetNameLength = 0;
	/* Decrypted local pet key */
	private byte[] decrypted_local_pet_key = null;
	private byte[] tmp = null;

	/* Minimum and maximum PIN size, and allocation size */
	private final static byte MAX_PIN_SIZE = 32; /* allocation size */
	private final static byte MIN_PIN_LEN = 4;
	private final static byte MAX_PIN_LEN = 15;

        /* Random data instance */
        private RandomData random = null;

	/* Variable handling the card lock state */
	public byte destroy_card = 0;

	/* Variable in eeprom handling the PetPin if the presentation has been performed OK (to limit brute force attacks) */
	private static final short MAX_PET_PIN_DERIVATION_FAILED_ATTEMPTS = (short)100;
	private short pet_pin_derivation_failed_attempts = 0;
	private byte dummy = 0;


	/* Secure channel challenge.
	 * This challenge is sent by the token when deriving the Pet PIN key, and must
	 * be used by the platform when mounting the secure channel to avoid replay of the
	 * first exchange.
	 */
	private byte[] sc_challenge = null;

	/* Local storage encryption provided by the upper layer
	 * NOTE: we use our local encryption provider to protect the PetName asset
	 */
        EncLocalStorage local_storage_enc = null;

	/* Secure channel initialisation checkpoint to check 
	 * (against fault injection attacks)
	 */
	public byte[] sc_checkpoint = null;

	protected WooKey(byte[] UserPin, byte[] PetPin, byte[] OurPrivKeyBuf, byte[] OurPubKeyBuf, byte[] WooKeyPubKeyBuf, byte[] LibECCparams, byte[] petname, short petname_length, byte max_pin_fails, short max_sc_fails, EncLocalStorage ls)
	{
		/* Secure channel initialization */
		schannel = new SecureChannel(UserPin, OurPrivKeyBuf, OurPubKeyBuf, WooKeyPubKeyBuf, LibECCparams);
		initialize_pet_pin(PetPin, max_pin_fails, MAX_PIN_SIZE);
		initialize_user_pin(UserPin, max_pin_fails, MAX_PIN_SIZE);
		sc_max_failed_attempts = max_sc_fails;
		if(petname_length > petname.length){
			ISOException.throwIt((short) 0x1122);
		}
		/* Local storage */
		local_storage_enc = ls;
		/* Locally encrypt the PetName */
		try{
			local_storage_enc.Encrypt(petname, (short) 0, (short) petname.length, petname, (short) 0);
		}
		catch(Exception e){
			ISOException.throwIt((short) 0x1122);
		}
		PetName = petname;
		PetNameLength = petname_length;
		/* Initialize the secure random source */
                random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		/* Erase all our sensitive buffers from flash now that we do not need them anymore ... */
		/* NOTE: we fill our Pins with random data to avoid known states attacks */
		random.generateData(PetPin, (short) 0, (short) PetPin.length);
		random.generateData(UserPin, (short) 0, (short) UserPin.length);
		Util.arrayFillNonAtomic(OurPrivKeyBuf, (short) 0, (short) OurPrivKeyBuf.length, (byte) 0);
		Util.arrayFillNonAtomic(OurPubKeyBuf, (short) 0, (short) OurPubKeyBuf.length, (byte) 0);
		Util.arrayFillNonAtomic(WooKeyPubKeyBuf, (short) 0, (short) WooKeyPubKeyBuf.length, (byte) 0);
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
		/* The secure channel challenge */
		sc_challenge = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayFillNonAtomic(sc_challenge, (short) 0, (short) sc_challenge.length, (byte) 0);
		sc_checkpoint = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
	}

	/* Self destroy the card */
	public void self_destroy_card(){
		/* We destroy all the assets */
		destroy_card = (byte) 0xaa;
		Util.arrayFillNonAtomic(Keys.OurPrivKeyBuf, (short) 0, (short) Keys.OurPrivKeyBuf.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.EncLocalPetSecretKey, (short) 0, (short) Keys.EncLocalPetSecretKey.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.EncLocalPetSecretKeyIV, (short) 0, (short) Keys.EncLocalPetSecretKeyIV.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.PetName, (short) 0, (short) Keys.PetName.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.PetPin, (short) 0, (short) Keys.PetPin.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.UserPin, (short) 0, (short) Keys.UserPin.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.OurPubKeyBuf, (short) 0, (short) Keys.OurPubKeyBuf.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.WooKeyPubKeyBuf, (short) 0, (short) Keys.WooKeyPubKeyBuf.length, (byte) 0);
		Util.arrayFillNonAtomic(Keys.LibECCparams, (short) 0, (short) Keys.LibECCparams.length, (byte) 0);
		/* Destroy secure channel assets */
		schannel.self_destroy_card();
		/* Lock our owner PINs */
		short i;
		for(i = 0; i < (short) (Keys.max_pin_tries + 1); i++){
			if(pet_pin != null){
				pet_pin.check(data, (short)0, (byte)0);
			}
			if(user_pin != null){
				user_pin.check(data, (short)0, (byte)0);
			}
		}
		
		/* Destroy local storage */
                local_storage_enc.destroy();
	}

	public void send_error(APDU apdu, byte[] err_data, short offset, short size, byte sw1, byte sw2){
                /* If we have such an error, we remove our secure channel */
		schannel.close_secure_channel();
		sc_checkpoint[0] = sc_checkpoint[1] = (byte)0x00;
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
				send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
				return;
			}
			if(sc_checkpoint[0] != (byte)0xaa){
				send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
				return;
			}
			if(sc_checkpoint[1] != (byte)0x55){
				send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
				return;
			}
			short outdata_len = schannel.receive_encrypted_apdu(apdu, data);
			schannel.send_encrypted_apdu(apdu, data, (short) 0, outdata_len, (byte) 0x90, (byte) 0x00);
			return;
		}
	}

	public void check_pin(APDU apdu, OwnerPIN pin, byte ins){
		/* The user is sending his pin, the secure channel must be initialized */
		if(schannel.is_secure_channel_initialized() == false){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[0] != (byte)0xaa){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[1] != (byte)0x55){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		short data_len = schannel.receive_encrypted_apdu(apdu, data);
		/* We cannot check the user pin before an authentication with the pet pin! */
		if((pin == user_pin) && (pet_pin.isValidated() == false)){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x01);
			return;
		}
		/* Get the real pin length (the PIN is padded to 16 bytes, the last byte represents the size) */
		if(data_len != (short) (MAX_PIN_LEN + 1)){
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
			schannel.send_encrypted_apdu(apdu, data, (short) 0, (short) 1, SW1_WARNING, (byte) 0x02);
			return;
		}
		short pin_len = (short)(data[MAX_PIN_LEN] & 0x00ff);
		/* Check pin real length */
		/* NOTE: we enforce here a minimum PIN length of 4 */
		if((pin_len < MIN_PIN_LEN) || (pin_len > MAX_PIN_LEN)){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x03);
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
				schannel.send_encrypted_apdu(apdu, data, (short) 0, (short) 1, SW1_WARNING, (byte) 0x03);
				return;
			}
			else{
				/* Respond an error with the number of remaining tries */
				data[0] = tries;
				schannel.send_encrypted_apdu(apdu, data, (short) 0, (short) 1, SW1_WARNING, (byte) 0x04);
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
		/* The user asks to change his pin, the secure channel must be initialized */
		if(schannel.is_secure_channel_initialized() == false){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[0] != (byte)0xaa){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[1] != (byte)0x55){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		short data_len = schannel.receive_encrypted_apdu(apdu, data);
		/* We check that we are already unlocked (both pet pin and user pin presented) */
		if((pet_pin.isValidated() == false) || (user_pin.isValidated() == false)){
			/* We are not authenticated, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x01);
			return;
		}
		/* Double check against faults */
		if(pet_pin.isValidated() == true){
			if(user_pin.isValidated() == true){
			}
		}
		else{
			/* We are not authenticated, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x01);
			return;
		}
		if((pet_pin.isValidated() == true) && (user_pin.isValidated() == true)){
			/* Try to change the pin */
			/* Get the real pin length (the PIN is padded to 16 bytes, the last byte represents the size) */
			if(pin == user_pin){
				if(data_len != (short)(MAX_PIN_LEN + 1)){
					/* Bad length, respond an error */
					schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x02);
					return;
				}
			}
			if(pin == pet_pin){
				if(data_len != ((short)(MAX_PIN_LEN + 1) + 64)){
					/* Bad length, respond an error */
					schannel.send_encrypted_apdu(apdu, data, (short) 0, (short) 0, SW1_WARNING, (byte) 0x02);
					return;
				}
			}
			short pin_len = (short)(data[MAX_PIN_LEN] & 0x00ff);

			/* Check new pin real length */
			if((pin_len < MIN_PIN_LEN) || (pin_len > MAX_PIN_LEN)){
				schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x03);
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
					schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x04);
					return;
				}
				/* In the case of the PET pin, we also have to re-encrypt our local pet key with the new pin */
				if(pin == pet_pin){
					/* Encrypt the local pet key master key and replace the old one */
					short i;
					for(i = 0; i < 4; i++){
						/* Chunk i */
						Util.arrayCopyNonAtomic(data, (short) ((short) 16 + (short) (i*16)), tmp, (short) 0, (short) 16);
						schannel.aes_cbc_ctx.aes_init(tmp, Keys.EncLocalPetSecretKeyIV, Aes.ENCRYPT);
						schannel.aes_cbc_ctx.aes(decrypted_local_pet_key, (short) (i*16), (short) 16, Keys.EncLocalPetSecretKey, (short) (i*16));
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
		else{
			/* We are not authenticated, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x01);
			return;
		}

	}

	public void set_pet_name(APDU apdu, byte ins){
		/* The user is sending the new pet name, the secure channel must be initialized */
		if(schannel.is_secure_channel_initialized() == false){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[0] != (byte)0xaa){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[1] != (byte)0x55){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		short data_len = schannel.receive_encrypted_apdu(apdu, data);
		/* We check that we are already unlocked (both pet pin and user pin presented) */
		if((pet_pin.isValidated() == false) || (user_pin.isValidated() == false)){
			/* We are not authenticated, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x01);
			return;
		}
		/* Double check against faults */
		if(pet_pin.isValidated() == true){
			if(user_pin.isValidated() == true){
			}
		}
		else{
			/* We are not authenticated, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x01);
			return;
		}
		if((pet_pin.isValidated() == true) && (user_pin.isValidated() == true)){
			/* Check maximum length for our pet name sentence ... */
			if(data_len > PetName.length){
				data[0] = (byte)data_len;
				data[1] = (byte)PetName.length;
				schannel.send_encrypted_apdu(apdu, data, (short) 0, (short) 2, SW1_WARNING, (byte) 0x02);
				return;
			}
			/* Modify the PET name (by transparently encrypting through local storage class) */
			Util.arrayFillNonAtomic(PetName, (short) 0, (short) PetName.length, (byte) 0);
			local_storage_enc.Encrypt(data, (short) 0, (short) PetName.length, PetName, (short) 0); 
			PetNameLength = data_len;
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0x90, (byte) 0x00);
			return;
		}
		else{
			/* We are not authenticated, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x01);
			return;
		}
	}

	public void user_pin_lock_token(APDU apdu, byte ins){
		/* The user asks to lock the token, the secure channel must be initialized */
		if(schannel.is_secure_channel_initialized() == false){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[0] != (byte)0xaa){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[1] != (byte)0x55){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		short data_len = schannel.receive_encrypted_apdu(apdu, data);
		if(data_len != 0){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x01);
			return;
		}
		/* If the session is not unlocked, we have nothing to do, else we lock it */
		if(user_pin.isValidated() == true){
			/* Double check against faults */
			if(user_pin.isValidated() != false){
				/* Note: we reset the pin. The side effect is a try counter reset, bu this is OK
				 * since an unlocked session means a reset of the counters anyways.
				 */
				user_pin.reset();
			}
		}
		schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0x90, (byte) 0x00);
		return;
	}

	public void full_lock_token(APDU apdu, byte ins){
		/* The user asks to fully lock the token, the secure channel must be initialized */
		if(schannel.is_secure_channel_initialized() == false){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[0] != (byte)0xaa){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[1] != (byte)0x55){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		short data_len = schannel.receive_encrypted_apdu(apdu, data);
		if(data_len != 0){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x01);
			return;
		}
		/* If the session is not unlocked, we have nothing to do, else we lock it */
		if(user_pin.isValidated() == true){
			/* Double check against faults */
			if(user_pin.isValidated() == true){
				/* Note: we reset the pin. The side effect is a try counter reset, bu this is OK
				 * since an unlocked session means a reset of the counters anyways.
				 */
				user_pin.reset();
			}
		}
		if(pet_pin.isValidated() == true){
			/* Double check against faults */
			if(pet_pin.isValidated() == true){
				/* Note: we reset the pin. The side effect is a try counter reset, bu this is OK
				 * since an unlocked session means a reset of the counters anyways.
				 */
				pet_pin.reset();
			}
		}
		/* Respond OK */
		schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, (byte) 0x90, (byte) 0x00);
		/* Kill the secure channel */
		schannel.close_secure_channel();
		sc_checkpoint[0] = sc_checkpoint[1] = (byte)0x00;
	}

	private void get_pet_name(APDU apdu, byte ins){
		if(schannel.is_secure_channel_initialized() == false){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[0] != (byte)0xaa){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[1] != (byte)0x55){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		short data_len = schannel.receive_encrypted_apdu(apdu, data);
		if(data_len != 0){
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x01);
			return;
		}
		if(pet_pin.isValidated() == false){
			/* We are not authenticated with the PET PIN, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x02);
			return;
		}
		/* Double check against faults */
		if(pet_pin.isValidated() == false){
			/* We are not authenticated with the PET PIN, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x02);
			return;
		}
		if(pet_pin.isValidated() == true){
			/* We send the pet name through the secure channel (with previously decrypting it through the local storage) */
			local_storage_enc.Decrypt(PetName, (short) 0, (short) PetName.length, data, (short) 0);
			schannel.send_encrypted_apdu(apdu, data, (short) 0, PetNameLength, (byte) 0x90, (byte) 0x00);
			return;
		}
		else{
			/* We are not authenticated with the PET PIN, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x02);
			return;
		}
	}

	/* Common service to provide secure random from the smartcard to the host */
	private void get_random(APDU apdu, byte ins){
		/* Asking for random needs a secure channel established as well as a user authentication */
                if(schannel.is_secure_channel_initialized() == false){
                        send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
                        return;
                }
		if(sc_checkpoint[0] != (byte)0xaa){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
		if(sc_checkpoint[1] != (byte)0x55){
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
			return;
		}
                short data_len = schannel.receive_encrypted_apdu(apdu, data);
                if(data_len != 1){
                        schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x01);
                        return;
                }
                /* We check that we are already unlocked (pet and user pin) */
                if((pet_pin.isValidated() == false) || (user_pin.isValidated() == false)){
                        /* We are not authenticated, ask for an authentication */
                        schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x02);
                        return;
                }
		/* Double check against faults */
		if(pet_pin.isValidated() == true){
			if(user_pin.isValidated() == true){
			}
		}
		else{
			/* We are not authenticated, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x02);
			return;
		}
		if((pet_pin.isValidated() == true) && (user_pin.isValidated() == true)){
                	/* This instruction expects a byte containing the size of random data to provide (maximum 256 bytes minus a HMAC size) */
			short rand_len = (short)(data[0] & 0x00ff);
			if(rand_len > schannel.get_max_sc_apdu_send_len()){
        	                schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x03);
                	        return;
			}
			try {
				random.generateData(data, (short) 0, rand_len);
			}
			catch(CryptoException exception){
                        	schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x04);
				return;
			}
                        schannel.send_encrypted_apdu(apdu, data, (short) 0, rand_len, (byte) 0x90, (byte) 0x00);
			return;
		}
		else{
			/* We are not authenticated, ask for an authentication */
			schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x02);
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

	/* Get a challenge */
	public void get_challenge(APDU apdu, byte ins){
		/* We ask to get a challenge inside of the secure channel */
	        if(schannel.is_secure_channel_initialized() == true){
                        schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
                        return;
                }
		/* This instruction expects no data */
		short receivedLen = apdu.setIncomingAndReceive();
		if(receivedLen != 0){
			ISOException.throwIt((short) 0xBBAA);
		}
		/* We generate a random challenge */
		random.generateData(sc_challenge, (short) 0, (short) sc_challenge.length);
		/* And send it */
		apdu.setOutgoing();
        	apdu.setOutgoingLength( (short) sc_challenge.length);
	        apdu.sendBytesLong(sc_challenge, (short) 0, (short) sc_challenge.length);

		return;
	}

	/* Derive the local pet key to send it to the platform */
	private void derive_local_pet_key(APDU apdu, byte ins){
		/* This command is the only one with get challenge that does not need a secure channel initialization ...
		 * (except for the select applet and secure channel negotiation ones of course)
		 * since the platform needs to decrypt its keys using this derivation *before* mounting
		 * the secure channel!
		 */
		/* Security against brute force */
		if(pet_pin_derivation_failed_attempts >= MAX_PET_PIN_DERIVATION_FAILED_ATTEMPTS){
				/* Self destroy the card ...*/
				self_destroy_card();
		}
		/* Double check against faults */
		if(MAX_PET_PIN_DERIVATION_FAILED_ATTEMPTS < pet_pin_derivation_failed_attempts){
				/* Self destroy the card ...*/
				self_destroy_card();
		}
	        if(schannel.is_secure_channel_initialized() == true){
                        schannel.send_encrypted_apdu(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x00);
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
		/* Decrypt the master key using AES CBC, secret IV, hash it with SHA-256 and send it */
		/* We hash with SHA-256 the two 32 bytes halves of the decrypted element, and we send the
		 * resulting 64 bytes (concatenation of the two 256 bits hashes).
		 */
		/* NOTE: we reuse our underlying AES CBC from secure channel for memory saving! */
		short i;
		for(i = 0; i < 4; i++){
			/* Chunk i */
			Util.arrayCopyNonAtomic(buffer, (short) ((short) ISO7816.OFFSET_CDATA + (short) (i*16)), tmp, (short) 0, (short) 16);
			schannel.aes_cbc_ctx.aes_init(tmp, Keys.EncLocalPetSecretKeyIV, Aes.DECRYPT);
			schannel.aes_cbc_ctx.aes(Keys.EncLocalPetSecretKey, (short) (i*16), (short) 16, decrypted_local_pet_key, (short) (i*16));
		}
		/* Hash the whole stuff in two parts with SHA-256 to have a one-way function */
		/* NOTE: we reuse our SHA-256 instance from the secure channel layer to save memory here!
		 */
		schannel.md.reset();
		schannel.md.doFinal(decrypted_local_pet_key, (short) 0, (short) (decrypted_local_pet_key.length / 2), data, (short) 0);
		schannel.md.reset();
		schannel.md.doFinal(decrypted_local_pet_key, (short) (decrypted_local_pet_key.length / 2), (short) (decrypted_local_pet_key.length / 2), data, (short) (decrypted_local_pet_key.length / 2));
		/* Send the decrypted local pet key */
	        apdu.setOutgoing();
        	apdu.setOutgoingLength( (short) (decrypted_local_pet_key.length));
	        apdu.sendBytesLong(data, (short) 0, (short) decrypted_local_pet_key.length);

		return;
	}

	public void secure_channel_init(APDU apdu, byte ins){
		/* Close secure channel first */
		schannel.close_secure_channel();
		sc_checkpoint[0] = sc_checkpoint[1] = (byte)0x00;
		/* Now go and try to open a secure channel */
		if(sc_failed_attempts >= sc_max_failed_attempts){
			/* Self destroy the card ...*/
			self_destroy_card();
			send_error(apdu, null, (short) 0, (short) 0, SW1_WARNING, (byte) 0x01);
			return;
		}
		try{
			/* Preincrement the failed attemps to limit tearing/fault attacks */
			sc_failed_attempts++;
			/* If the challenge is zeroized, throw an exception!
			 * This means that the 'get_challenge' function has not been called before mounting the channel.
			 */
			Util.arrayFillNonAtomic(tmp, (short) 0, (short) tmp.length, (byte) 0);
			byte check_sc_challenge_zero = Util.arrayCompare(sc_challenge, (short) 0, tmp, (short) 0, (short) sc_challenge.length);
			if(check_sc_challenge_zero == (byte) 0){
				CryptoException.throwIt(CryptoException.INVALID_INIT);
			}
			else{
				/* Double check here */
				if(check_sc_challenge_zero == (byte) 0){
					CryptoException.throwIt(CryptoException.INVALID_INIT);
				}
				schannel.secure_channel_init(apdu, data, sc_challenge);
			}
		}
		catch(Exception e){
			sc_checkpoint[0] = sc_checkpoint[1] = (byte)0x00;
			data[0] = (byte) ((short)(sc_max_failed_attempts - sc_failed_attempts) >>> 8);
			data[1] = (byte) ((sc_max_failed_attempts - sc_failed_attempts) & 0xff);
			send_error(apdu, data, (short) 0, (short) 2, SW1_WARNING, (byte) 0x00);
			return;
		}
		/* Reset the failed_attempts counter if we have successfully established a channel */
		sc_failed_attempts = 0;
		/* Reset the counter handling brute force limitation (the Pet PIN was OK since we have
		 * mounted the secure channel).
		 */
		pet_pin_derivation_failed_attempts = 0;
		/* The secure channel has been sucessfully mounted, set the challenge to zero */
		Util.arrayFillNonAtomic(sc_challenge, (short) 0, (short) sc_challenge.length, (byte) 0);
		/* Channel successfully established, activate our check points */
		sc_checkpoint[0] = (byte) 0xaa;
		sc_checkpoint[1] = (byte) 0x55;
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
			case TOKEN_INS_GET_CHALLENGE:
				get_challenge(apdu, TOKEN_INS_GET_CHALLENGE);
				return true;
			default:
				return false;
		}

	}
}

