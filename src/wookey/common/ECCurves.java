import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class ECCurves {
	/* Available curves. */
        private static final byte FRP256V1 = 0;
        private static final byte BRAINPOOLP256R1 = 1;
        private static final byte SECP256R1 = 2;
        private static final byte NONE = 3;

	/* The parameters */
	public byte[] p = null;
	public byte[] a = null;
	public byte[] b = null;
	public byte[] G = null;
	public byte[] q = null;
	public byte[] cofactor = null;

	private byte[] ECCparams = null;

	/* The ECDSA signature context */
	private Signature sigECDSA = null;
	/* ECDSA signature length */
	public short sigECDSAlen = 0;

	/* The ECDH context */
	private KeyAgreement ecdh = null;

        /* ECDH keypair */
	/* NOTE: We would want to make this key *transient*, but this is
         * unfortunately not possible on all cards (for instance, NXP JCOP cards
	 * perform an exception when trying to create such asymmetric transient keys ...).
	 * In order to be able to do it on compatible cards, we use a try and except paradigm:
	 * we try to create such keys as transient in RAM, and if not possible we create them as
	 * non transient in EEPROM.
	 */
	private ECKeyPair kpECDHWrapper = null;
        private KeyPair kpECDH = null;
        private ECPrivateKey privKeyECDH = null;
        private ECPublicKey pubKeyECDH = null;

	/* Destroy local assets */
	public void destroy(){
		if(privKeyECDH != null){
			privKeyECDH.clearKey();
		}
		if(pubKeyECDH != null){
			pubKeyECDH.clearKey();
		}
		if(p != null){
	                Util.arrayFillNonAtomic(p, (short) 0, (short) p.length, (byte) 0);
		}
		if(a != null){
	                Util.arrayFillNonAtomic(a, (short) 0, (short) a.length, (byte) 0);
		}
		if(b != null){
	                Util.arrayFillNonAtomic(b, (short) 0, (short) b.length, (byte) 0);
		}
		if(G != null){
	                Util.arrayFillNonAtomic(G, (short) 0, (short) G.length, (byte) 0);
		}
		if(q != null){
	                Util.arrayFillNonAtomic(q, (short) 0, (short) q.length, (byte) 0);
		}
		if(cofactor != null){
	                Util.arrayFillNonAtomic(cofactor, (short) 0, (short) cofactor.length, (byte) 0);
		}
		if(ECCparams != null){
	                Util.arrayFillNonAtomic(ECCparams, (short) 0, (short) ECCparams.length, (byte) 0);
		}

		return;
	}
	
	protected ECCurves(byte[] LibECCparams){
		/* Get the curve we must use from the LibECCparams.
		 */
		byte asked_curve = NONE;
		/* Parse the two bytes providing the curve and the algoithm. We only accept
		 * FRP256V1/BRAINPOOLP256R1/SECP256R1 for the curves and ECDSA for the signing
		 * algorithm.
		 * On the libecc side, we have ECDSA = 1, FRP256V1=1, BRAINPOOLP256R1=8, SECP256R1=4.
		 */
		if(LibECCparams.length != 2){
			CryptoException.throwIt(CryptoException.INVALID_INIT);
		}
		/* Byte 0 is the signing algorithm type (only ECDSA supported) */
		if(LibECCparams[0] != 1){
			CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
		}
		switch(LibECCparams[1]){
			case 1:
				asked_curve = FRP256V1;
				break;
			case 4:
				asked_curve = SECP256R1;
				break;
			case 8:
				asked_curve = BRAINPOOLP256R1;
				break;
			default:
				asked_curve = NONE;
				break;
		}	

		switch(asked_curve){
			case FRP256V1:
				p = Frp256v1.p;
				a = Frp256v1.a;
				b = Frp256v1.b;
				G = Frp256v1.G;
				q = Frp256v1.q;
				cofactor = Frp256v1.cofactor;
				sigECDSAlen = 64;
				break;
			case BRAINPOOLP256R1:
				p = Brainpoolp256r1.p;
				a = Brainpoolp256r1.a;
				b = Brainpoolp256r1.b;
				G = Brainpoolp256r1.G;
				q = Brainpoolp256r1.q;
				cofactor = Brainpoolp256r1.cofactor;
				sigECDSAlen = 64;
				break;
			case SECP256R1:
				p = Secp256r1.p;
				a = Secp256r1.a;
				b = Secp256r1.b;
				G = Secp256r1.G;
				q = Secp256r1.q;
				cofactor = Secp256r1.cofactor;
				sigECDSAlen = 64;
				break;
			default:
				CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
				break;
		}
		ECCparams = new byte[(short) LibECCparams.length];
		Util.arrayCopyNonAtomic(LibECCparams, (short) 0, ECCparams, (short)0, (short)LibECCparams.length);
		initialize_eeprom();
	}

	public static short get_EC_sig_len(byte[] LibECCparams){
		/* Get the curve we must use from the LibECCparams.
		 */
		byte asked_curve = NONE;
		/* Parse the two bytes providing the curve and the algoithm. We only accept
		 * FRP256V1/BRAINPOOLP256R1/SECP256R1 for the curves and ECDSA for the signing
		 * algorithm.
		 * On the libecc side, we have ECDSA = 1, FRP256V1=1, BRAINPOOLP256R1=8, SECP256R1=4.
		 */
		if(LibECCparams.length != 2){
			CryptoException.throwIt(CryptoException.INVALID_INIT);
		}
		/* Byte 0 is the signing algorithm type (only ECDSA supported) */
		if(LibECCparams[0] != 1){
			CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
		}
		switch(LibECCparams[1]){
			case 1:
				asked_curve = FRP256V1;
				break;
			case 4:
				asked_curve = SECP256R1;
				break;
			case 8:
				asked_curve = BRAINPOOLP256R1;
				break;
			default:
				asked_curve = NONE;
				break;
		}	

		switch(asked_curve){
			case FRP256V1:
				return 64;
			case BRAINPOOLP256R1:
				return 64;
			case SECP256R1:
				return 64;
			default:
				CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
				break;
		}

		return 0;
	}

	public void initialize_EC_key_pair_context(byte[] PrivKeyBuf, boolean priv_transient, byte[] PubKeyBuf, ECKeyPair kp){
		/* NOTE: When asked to create a transient private part of the key pair, some javacards throw an exception because
		 * of a probable lack of support. Hence, we first try to create transient keys, and catch the exception to create non transient
		 * keys if the first case is not possible.
		 */
		if(priv_transient == true){
			try {
				kp.PrivKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, true);
			}
			catch(CryptoException e){
                                /* Our card might not support the 'true' flag for 'boolean keyEncryption': this however
                                 * does not mean that the proprietary layer does not support it ... (see the Javacard spec).
                                 * For instance JCOP cards throw an exception while the key is still encrypted ...
                                 */
				try {
					kp.PrivKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false);
				}
				catch(CryptoException e1){
					/* We do not have enough RAM ... Fall back to the non transient private key */
					try {
						kp.PrivKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, true);
					}
					catch(CryptoException e2){
						kp.PrivKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
					}
				}
			}
		}
		else{
			try {
				kp.PrivKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, true);
			}
			catch(CryptoException e3){
				kp.PrivKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
			}
		}
		kp.PrivKey.setFieldFP(p, (short) 0, (short) p.length);
		kp.PrivKey.setA(a, (short) 0, (short) a.length);
		kp.PrivKey.setB(b, (short) 0, (short) b.length);
		kp.PrivKey.setG(G, (short) 0, (short) G.length);
		kp.PrivKey.setR(q, (short) 0, (short) q.length);
		if(PrivKeyBuf != null){
			kp.PrivKey.setS(PrivKeyBuf, (short) 0, (short) PrivKeyBuf.length);
		}

		kp.PubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);	
		kp.PubKey.setFieldFP(p, (short) 0, (short) p.length);
		kp.PubKey.setA(a, (short) 0, (short) a.length);
		kp.PubKey.setB(b, (short) 0, (short) b.length);
		kp.PubKey.setG(G, (short) 0, (short) G.length);
		kp.PubKey.setR(q, (short) 0, (short) q.length);
		if(PubKeyBuf != null){
			kp.PubKey.setW(PubKeyBuf, (short) 0, (short) PubKeyBuf.length);
		}
			
		kp.kp = new KeyPair(kp.PubKey, kp.PrivKey);
	}

	public void initialize_eeprom(){
		/* Initialize our ECDSA and ECDH signature contexts */
		sigECDSA = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
		/* ECDH key pair.
		/* NOTE: We would want to make this key *transient*, but this is
        	 * unfortunately not possible on all cards (for instance, NXP JCOP cards
		 * perform an exception when trying to create such asymmetric transient keys ...).
		 * In order to be able to do it on compatible cards, we use a try and except paradigm:
		 * we try to create such keys as transient in RAM, and if not possible we create them as
		 * non transient in EEPROM.
		 */
		kpECDHWrapper = new ECKeyPair();
		/* The following initialization tries first and initialization in RAM, and
		 * fallbacks to EEPROM if not possible ...
		 */
		initialize_EC_key_pair_context(null, true, null, kpECDHWrapper);
		kpECDH = kpECDHWrapper.kp;
		privKeyECDH = kpECDHWrapper.PrivKey;
		pubKeyECDH  = kpECDHWrapper.PubKey;
	}

	/* Generate the ECDH shared secret. Uses a temporary working buffer provided as an argument. */
        public short ecdh_shared_secret(byte[] shared_point, short indataoffset, short indatalen, byte[] shared_secret, byte[] working_buffer){
                try{
			short BN_len = (short) p.length;

			/* Check that the last coordinate is 0x01 in Bignum () */
			short i;
			for(i = (short)(2 * (indatalen / 3)); i < (short)(indatalen-1); i++){
				if(shared_point[i] != 0x00){
					CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
				}
			}
			if(shared_point[(short)(indatalen-1)] != 0x01){
				CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
			}

                        /* Generate our ECDH private and public parts */
                        kpECDH.genKeyPair();

                        ecdh.init(privKeyECDH);
                        /* First, we extract the point.
                        /* Internal representation is an uncompressed point.
                         */
                        short sp_length = (short) (2 * (indatalen / 3) + 1);
                        working_buffer[0] = 0x04;
                        Util.arrayCopyNonAtomic(shared_point, indataoffset, working_buffer, (short) 1, (short) (sp_length - 1));

                        short len = ecdh.generateSecret(working_buffer, (short) 0, sp_length, shared_secret, (short) 0);

			/* The ECDH is done, we clean up the ECDH private key since we don't need it anymore ... */
			Util.arrayFillNonAtomic(working_buffer, (short) 0, (short) working_buffer.length, (byte) 0x0);
			privKeyECDH.setS(working_buffer, (short) 0, BN_len);

                        /* We override shared_point with our public key, which is d*G */
                        pubKeyECDH.getW(working_buffer, (short) 0);
                        Util.arrayCopyNonAtomic(working_buffer, (short) 1, shared_point, (short) 0, (short) (sp_length - 1));

                        return len;
                }
                catch(CryptoException exception)
                {
                    switch(exception.getReason()){
                        case CryptoException.ILLEGAL_USE:
                                ISOException.throwIt((short) 0xECD0);
                                break;
                        case CryptoException.ILLEGAL_VALUE:
                                ISOException.throwIt((short) 0xECD1);
                                break;
                        case CryptoException.INVALID_INIT:
                                ISOException.throwIt((short) 0xECD2);
                                break;
                        case CryptoException.NO_SUCH_ALGORITHM:
                                ISOException.throwIt((short) 0xECD3);
                                break;
                        case CryptoException.UNINITIALIZED_KEY:
                                ISOException.throwIt((short) 0xECD4);
                                break;
                        default:
                                ISOException.throwIt((short) 0xECD5);
                                break;
                        }
                }
                return 0;
        }

	/* ECDSA signature generation. Uses a temporary working buffer provided as an argument. */
	public short ecdsa_sign(byte[] indata, short indataoffset, short indatalen, byte[] outdata, short outdataoffset, byte[] working_buffer, ECPrivateKey OurPrivKey){
		try{
			sigECDSA.init(OurPrivKey, Signature.MODE_SIGN);
			short structured_sequence_siglen = sigECDSA.sign(indata, indataoffset, indatalen, working_buffer, (short) 0);
			short r_size = 0;
			short s_size = 0;
			short siglen = (short) (2 * p.length);
			/* TODO: this is a lose way of decapsulating (r, s) from the SEQUENCE ASN.1 representation ...
			 * This is OK in our specific use case, but a more flexible/robust way should be implemented here.
			 */
			/* First, zeroize our output buffer */
	                Util.arrayFillNonAtomic(outdata, outdataoffset, siglen, (byte) 0);	
			if(working_buffer[0] != 0x30){
                        	ISOException.throwIt((short) 0xECE0);	
			}
			if(working_buffer[1] != (short)(structured_sequence_siglen - 2)){
                        	ISOException.throwIt((short) 0xECE1);
			}
		
			if(working_buffer[2] != 0x02){
                        	ISOException.throwIt((short) 0xECE2);
			}
			r_size = working_buffer[3];
			if(working_buffer[4] == 0x00){
				/* Check the most significant bit of the byte after 0x00, and remove the 0x00 if it is set
				 * (see the ASN.1 encoding rules for INTEGER objects). Do not remove it if the expected r length
				 * is realized with the leading 0x00 ...
				 */
				if(((working_buffer[5] & (byte)0x80) != 0) && (r_size == (short) (p.length + 1))){
					/* Sanity check */
					if(r_size > (short) (p.length + 1)){
                		        	ISOException.throwIt((short) 0xECE3);
					}
					r_size--;
       		 			Util.arrayCopyNonAtomic(working_buffer, (short) 5, outdata, outdataoffset, r_size);
				}
				else{
					/* Sanity check */
					if(r_size > p.length){
                		        	ISOException.throwIt((short) 0xECE3);
					}
       	 				Util.arrayCopyNonAtomic(working_buffer, (short) 4, outdata, (short) (outdataoffset + p.length - r_size), r_size);
				}
			}
			else{
				/* Sanity check */
				if(r_size > p.length){
               		        	ISOException.throwIt((short) 0xECE3);
				}
       	 			Util.arrayCopyNonAtomic(working_buffer, (short) 4, outdata, (short) (outdataoffset + p.length - r_size), r_size);
			}
			if(working_buffer[(short)(4 + working_buffer[3])] != 0x02){
                        	ISOException.throwIt((short) 0xECE3);
			}
			s_size = working_buffer[(short)(4 + working_buffer[3] + 1)];
			if(working_buffer[(short)(4 + working_buffer[3] + 2)] == 0x00){
				/* Check the most significant bit of the byte after 0x00, and remove the 0x00 if it is set
				 * (see the ASN.1 encoding rules for INTEGER objects). Do not remove it if the expected s length
                                 * is realized with the leading 0x00 ...
				 */
				if(((working_buffer[(short)(4 + working_buffer[3] + 2 + 1)] & (byte)0x80) != 0) && (s_size == (short) (p.length + 1))){
					/* Sanity check */
					if(s_size > (short) (p.length + 1)){
                		        	ISOException.throwIt((short) 0xECE3);
					}
					s_size--;
       		 			Util.arrayCopyNonAtomic(working_buffer, (short) (4 + working_buffer[3] + 3), outdata, (short) (outdataoffset + p.length + p.length - s_size), s_size);
				}
				else{
					/* Sanity check */
					if(s_size > p.length){
                		        	ISOException.throwIt((short) 0xECE3);
					}
       	 				Util.arrayCopyNonAtomic(working_buffer, (short) (4 + working_buffer[3] + 2), outdata, (short) (outdataoffset + p.length + p.length - s_size), s_size);
				}
			}
			else{
				/* Sanity check */
				if(s_size > p.length){
               		        	ISOException.throwIt((short) 0xECE3);
				}
       	 			Util.arrayCopyNonAtomic(working_buffer, (short) (4 + working_buffer[3] + 2), outdata, (short) (outdataoffset + p.length + p.length - s_size), s_size);
			}
			/* Our signature length is 2 Fp big numbers */
			return siglen;
		}
		catch(CryptoException exception)
        	{
        	    switch(exception.getReason()){
	                case CryptoException.ILLEGAL_USE:
                        	ISOException.throwIt((short) 0xECD0);
                	        break;
        	        case CryptoException.ILLEGAL_VALUE:
	                        ISOException.throwIt((short) 0xECD1);
        	                break;
	                case CryptoException.INVALID_INIT:
                	        ISOException.throwIt((short) 0xECD2);
        	                break;
	                case CryptoException.NO_SUCH_ALGORITHM:
               	         	ISOException.throwIt((short) 0xECD3);
        	                break;
	                case CryptoException.UNINITIALIZED_KEY:
                	        ISOException.throwIt((short) 0xECD4);
	                        break;
        	       	default:
                        	ISOException.throwIt((short) 0xECD5);
                        	break;
            		}
        	}
		return 0;
	}

	/* ECDSA signature verification. Uses a temporary working buffer provided as an argument. */
	public boolean ecdsa_verify(byte[] indata, short indataoffset, short indatalen, byte[] sigBuf, short sigoffset, short siglen, byte[] working_buffer, ECPublicKey WooKeyPubKey){
		try{
			sigECDSA.init(WooKeyPubKey, Signature.MODE_VERIFY);
			/* The structured_sig buffer contains a structured (r, s) signature with an ASN.1 sequence
			 * encapsulating two integers */
			short r_length = (short) (siglen / 2);
			short s_length = (short) (siglen / 2);
			/* TODO: this is a lose way of encapsulating (r, s) in ASN.1, and this will not work for very large integers ...
			 * This is OK in our specific use case, but a more flexible/robust way should be implemented here.
			 */
			/* First of all, we remove all the leading zeros from r and s */
			short r_start_offset = 0;
			short s_start_offset = r_length;
			short i, out_sig_len = siglen;
			for(i = 0; i < r_length; i++){
				if(sigBuf[(short) (sigoffset + i)] != 0x00){
					break;
				}
				r_start_offset++;
			}
			for(i = 0; i < s_length; i++){
				if(sigBuf[(short) (sigoffset + (short) (siglen / 2) + i)] != 0x00){
					break;
				}
				s_start_offset++;
			}
			r_length = (short) (r_length - r_start_offset);
			s_length = (short) (s_length - (s_start_offset - (short) (siglen / 2)));
			out_sig_len = (short) (r_length + s_length);
			/* Then, we format our buffer */
			working_buffer[0] = (byte) 0x30;
			working_buffer[1] = (byte) (out_sig_len + 4);
			short s_offset = (short) 0;
			if((sigBuf[(short) (sigoffset + r_start_offset)] & ((byte) 0x80)) == (byte)0x80){
				working_buffer[1]++;
				out_sig_len++;
				working_buffer[2] = 0x02;
				working_buffer[3] = (byte)(r_length + 1);
				working_buffer[4] = 0x00;
	        		Util.arrayCopyNonAtomic(sigBuf, (short) (sigoffset + r_start_offset), working_buffer, (short) 5, r_length);
				s_offset = (short)(5 + r_length);
			}
			else{
				working_buffer[2] = 0x02;
				working_buffer[3] = (byte) (r_length);
	        		Util.arrayCopyNonAtomic(sigBuf, (short) (sigoffset + r_start_offset), working_buffer, (short) 4, r_length);	
				s_offset = (short)(4 + r_length);
			}
			if((sigBuf[(short) (sigoffset + s_start_offset)] & ((byte) 0x80)) == (byte)0x80){
				working_buffer[1]++;
				out_sig_len++;
				working_buffer[s_offset] = 0x02;
				working_buffer[(short)(s_offset + 1)] = (byte)(s_length + 1);
				working_buffer[(short)(s_offset + 2)] = 0x00;
	        		Util.arrayCopyNonAtomic(sigBuf, (short) (sigoffset + s_start_offset), working_buffer, (short) (s_offset + 3), s_length);
			}
			else{
				working_buffer[s_offset] = 0x02;
				working_buffer[(short)(s_offset + 1)] = (byte)(s_length);
	        		Util.arrayCopyNonAtomic(sigBuf, (short) (sigoffset + s_start_offset), working_buffer, (short) (s_offset + 2), s_length);	
			}
			return sigECDSA.verify(indata, indataoffset, indatalen, working_buffer, (short) 0, (short) (out_sig_len + 6));
		}
		catch(CryptoException exception)
        	{
        	    switch(exception.getReason()){
	                case CryptoException.ILLEGAL_USE:
                        	ISOException.throwIt((short) 0xECD0);
                	        break;
        	        case CryptoException.ILLEGAL_VALUE:
	                        ISOException.throwIt((short) 0xECD1);
        	                break;
	                case CryptoException.INVALID_INIT:
                	        ISOException.throwIt((short) 0xECD2);
        	                break;
	                case CryptoException.NO_SUCH_ALGORITHM:
               	         	ISOException.throwIt((short) 0xECD3);
        	                break;
	                case CryptoException.UNINITIALIZED_KEY:
                	        ISOException.throwIt((short) 0xECD4);
	                        break;
        	       	default:
                        	ISOException.throwIt((short) 0xECD5);
                        	break;
            		}
        	}
		return false;

	}

	/* Nested classes for parameters */
	private static class Frp256v1 {
		/* FRP256V1 parameters */
        	static final byte[] p = {
	        (byte)0xf1, (byte)0xfd, (byte)0x17, (byte)0x8c, (byte)0x0b, (byte)0x3a, (byte)0xd5, (byte)0x8f,
        	(byte)0x10, (byte)0x12, (byte)0x6d, (byte)0xe8, (byte)0xce, (byte)0x42, (byte)0x43, (byte)0x5b,
       		(byte)0x39, (byte)0x61, (byte)0xad, (byte)0xbc, (byte)0xab, (byte)0xc8, (byte)0xca, (byte)0x6d,
        	(byte)0xe8, (byte)0xfc, (byte)0xf3, (byte)0x53, (byte)0xd8, (byte)0x6e, (byte)0x9c, (byte)0x03
        	};

        	static final byte[] a = {
	        (byte)0xf1, (byte)0xfd, (byte)0x17, (byte)0x8c, (byte)0x0b, (byte)0x3a, (byte)0xd5, (byte)0x8f,
	        (byte)0x10, (byte)0x12, (byte)0x6d, (byte)0xe8, (byte)0xce, (byte)0x42, (byte)0x43, (byte)0x5b,
	        (byte)0x39, (byte)0x61, (byte)0xad, (byte)0xbc, (byte)0xab, (byte)0xc8, (byte)0xca, (byte)0x6d,
	        (byte)0xe8, (byte)0xfc, (byte)0xf3, (byte)0x53, (byte)0xd8, (byte)0x6e, (byte)0x9c, (byte)0x00
        	};

        	static final byte[] b = {
        	(byte)0xee, (byte)0x35, (byte)0x3f, (byte)0xca, (byte)0x54, (byte)0x28, (byte)0xa9, (byte)0x30,
	        (byte)0x0d, (byte)0x4a, (byte)0xba, (byte)0x75, (byte)0x4a, (byte)0x44, (byte)0xc0, (byte)0x0f,
        	(byte)0xdf, (byte)0xec, (byte)0x0c, (byte)0x9a, (byte)0xe4, (byte)0xb1, (byte)0xa1, (byte)0x80,
	        (byte)0x30, (byte)0x75, (byte)0xed, (byte)0x96, (byte)0x7b, (byte)0x7b, (byte)0xb7, (byte)0x3f
        	};

       		static final byte[] G = {
		(byte)0x04, (byte)0xb6, (byte)0xb3, (byte)0xd4, (byte)0xc3, (byte)0x56, (byte)0xc1, (byte)0x39, (byte)0xeb,
	        (byte)0x31, (byte)0x18, (byte)0x3d, (byte)0x47, (byte)0x49, (byte)0xd4, (byte)0x23, (byte)0x95,
        	(byte)0x8c, (byte)0x27, (byte)0xd2, (byte)0xdc, (byte)0xaf, (byte)0x98, (byte)0xb7, (byte)0x01,
	        (byte)0x64, (byte)0xc9, (byte)0x7a, (byte)0x2d, (byte)0xd9, (byte)0x8f, (byte)0x5c, (byte)0xff,
	        (byte)0x61, (byte)0x42, (byte)0xe0, (byte)0xf7, (byte)0xc8, (byte)0xb2, (byte)0x04, (byte)0x91,
        	(byte)0x1f, (byte)0x92, (byte)0x71, (byte)0xf0, (byte)0xf3, (byte)0xec, (byte)0xef, (byte)0x8c,
	        (byte)0x27, (byte)0x01, (byte)0xc3, (byte)0x07, (byte)0xe8, (byte)0xe4, (byte)0xc9, (byte)0xe1,
        	(byte)0x83, (byte)0x11, (byte)0x5a, (byte)0x15, (byte)0x54, (byte)0x06, (byte)0x2c, (byte)0xfb
        	};

        	static final byte[] q = {
	        (byte)0xf1, (byte)0xfd, (byte)0x17, (byte)0x8c, (byte)0x0b, (byte)0x3a, (byte)0xd5, (byte)0x8f,
        	(byte)0x10, (byte)0x12, (byte)0x6d, (byte)0xe8, (byte)0xce, (byte)0x42, (byte)0x43, (byte)0x5b,
	        (byte)0x53, (byte)0xdc, (byte)0x67, (byte)0xe1, (byte)0x40, (byte)0xd2, (byte)0xbf, (byte)0x94,
        	(byte)0x1f, (byte)0xfd, (byte)0xd4, (byte)0x59, (byte)0xc6, (byte)0xd6, (byte)0x55, (byte)0xe1
        	};
        	static final byte[] cofactor = { (byte) 0x01 };
	}
	private static class Brainpoolp256r1 {
		/* BRAINPOOLP256R1 parameters */
        	static final byte[] p = {
	        (byte)0xA9, (byte)0xFB, (byte)0x57, (byte)0xDB, (byte)0xA1, (byte)0xEE, (byte)0xA9, (byte)0xBC,
        	(byte)0x3E, (byte)0x66, (byte)0x0A, (byte)0x90, (byte)0x9D, (byte)0x83, (byte)0x8D, (byte)0x72,
	        (byte)0x6E, (byte)0x3B, (byte)0xF6, (byte)0x23, (byte)0xD5, (byte)0x26, (byte)0x20, (byte)0x28,
        	(byte)0x20, (byte)0x13, (byte)0x48, (byte)0x1D, (byte)0x1F, (byte)0x6E, (byte)0x53, (byte)0x77
        	};

        	static final byte[] a = {
	        (byte)0x7D, (byte)0x5A, (byte)0x09, (byte)0x75, (byte)0xFC, (byte)0x2C, (byte)0x30, (byte)0x57, (byte)0xEE, (byte)0xF6, (byte)0x75, (byte)0x30,
        	(byte)0x41, (byte)0x7A, (byte)0xFF, (byte)0xE7, (byte)0xFB, (byte)0x80, (byte)0x55, (byte)0xC1, (byte)0x26, (byte)0xDC, (byte)0x5C, (byte)0x6C,
	        (byte)0xE9, (byte)0x4A, (byte)0x4B, (byte)0x44, (byte)0xF3, (byte)0x30, (byte)0xB5, (byte)0xD9
        	};

        	static final byte[] b = {
	        (byte)0x26, (byte)0xDC, (byte)0x5C, (byte)0x6C, (byte)0xE9, (byte)0x4A, (byte)0x4B, (byte)0x44, (byte)0xF3, (byte)0x30, (byte)0xB5, (byte)0xD9,
        	(byte)0xBB, (byte)0xD7, (byte)0x7C, (byte)0xBF, (byte)0x95, (byte)0x84, (byte)0x16, (byte)0x29, (byte)0x5C, (byte)0xF7, (byte)0xE1, (byte)0xCE,
	        (byte)0x6B, (byte)0xCC, (byte)0xDC, (byte)0x18, (byte)0xFF, (byte)0x8C, (byte)0x07, (byte)0xB6
        	};

       		static final byte[] G = {
		(byte)0x04, (byte)0x8B, (byte)0xD2, (byte)0xAE, (byte)0xB9, (byte)0xCB, (byte)0x7E, (byte)0x57, (byte)0xCB, (byte)0x2C, (byte)0x4B, (byte)0x48, (byte)0x2F,
	        (byte)0xFC, (byte)0x81, (byte)0xB7, (byte)0xAF, (byte)0xB9, (byte)0xDE, (byte)0x27, (byte)0xE1, (byte)0xE3, (byte)0xBD, (byte)0x23, (byte)0xC2,
        	(byte)0x3A, (byte)0x44, (byte)0x53, (byte)0xBD, (byte)0x9A, (byte)0xCE, (byte)0x32, (byte)0x62,
		(byte)0x54, (byte)0x7E, (byte)0xF8, (byte)0x35, (byte)0xC3, (byte)0xDA, (byte)0xC4, (byte)0xFD, (byte)0x97, (byte)0xF8, (byte)0x46, (byte)0x1A,
		(byte)0x14, (byte)0x61, (byte)0x1D, (byte)0xC9, (byte)0xC2, (byte)0x77, (byte)0x45, (byte)0x13, (byte)0x2D, (byte)0xED, (byte)0x8E, (byte)0x54,
		(byte)0x5C, (byte)0x1D, (byte)0x54, (byte)0xC7, (byte)0x2F, (byte)0x04, (byte)0x69, (byte)0x97
        	};

        	static final byte[] q = {
		(byte)0xA9, (byte)0xFB, (byte)0x57, (byte)0xDB, (byte)0xA1, (byte)0xEE, (byte)0xA9, (byte)0xBC, (byte)0x3E, (byte)0x66, (byte)0x0A, (byte)0x90,
        	(byte)0x9D, (byte)0x83, (byte)0x8D, (byte)0x71, (byte)0x8C, (byte)0x39, (byte)0x7A, (byte)0xA3, (byte)0xB5, (byte)0x61, (byte)0xA6, (byte)0xF7,
        	(byte)0x90, (byte)0x1E, (byte)0x0E, (byte)0x82, (byte)0x97, (byte)0x48, (byte)0x56, (byte)0xA7
                };
        	static final byte[] cofactor = { (byte) 0x01};
	}
	private static class Secp256r1 {
		/* SECP256R1 parameters */
        	static final byte[] p = {
	        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01,
        	(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
	        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        	(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
        	};

        	static final byte[] a = {
	        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01,
        	(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
	        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        	(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
        	};

        	static final byte[] b = {
	        (byte)0x5A, (byte)0xC6, (byte)0x35, (byte)0xD8, (byte)0xAA, (byte)0x3A, (byte)0x93, (byte)0xE7,
        	(byte)0xB3, (byte)0xEB, (byte)0xBD, (byte)0x55, (byte)0x76, (byte)0x98, (byte)0x86, (byte)0xBC,
	        (byte)0x65, (byte)0x1D, (byte)0x06, (byte)0xB0, (byte)0xCC, (byte)0x53, (byte)0xB0, (byte)0xF6,
        	(byte)0x3B, (byte)0xCE, (byte)0x3C, (byte)0x3E, (byte)0x27, (byte)0xD2, (byte)0x60, (byte)0x4B
        	};

       		static final byte[] G = {
		(byte)0x04, (byte)0x6B, (byte)0x17, (byte)0xD1, (byte)0xF2, (byte)0xE1, (byte)0x2C, (byte)0x42, (byte)0x47,
	        (byte)0xF8, (byte)0xBC, (byte)0xE6, (byte)0xE5, (byte)0x63, (byte)0xA4, (byte)0x40, (byte)0xF2,
        	(byte)0x77, (byte)0x03, (byte)0x7D, (byte)0x81, (byte)0x2D, (byte)0xEB, (byte)0x33, (byte)0xA0,
	        (byte)0xF4, (byte)0xA1, (byte)0x39, (byte)0x45, (byte)0xD8, (byte)0x98, (byte)0xC2, (byte)0x96,
	        (byte)0x4F, (byte)0xE3, (byte)0x42, (byte)0xE2, (byte)0xFE, (byte)0x1A, (byte)0x7F, (byte)0x9B,
        	(byte)0x8E, (byte)0xE7, (byte)0xEB, (byte)0x4A, (byte)0x7C, (byte)0x0F, (byte)0x9E, (byte)0x16,
	        (byte)0x2B, (byte)0xCE, (byte)0x33, (byte)0x57, (byte)0x6B, (byte)0x31, (byte)0x5E, (byte)0xCE,
        	(byte)0xCB, (byte)0xB6, (byte)0x40, (byte)0x68, (byte)0x37, (byte)0xBF, (byte)0x51, (byte)0xF5
        	};

        	static final byte[] q = {
	        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        	(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
	        (byte)0xBC, (byte)0xE6, (byte)0xFA, (byte)0xAD, (byte)0xA7, (byte)0x17, (byte)0x9E, (byte)0x84,
        	(byte)0xF3, (byte)0xB9, (byte)0xCA, (byte)0xC2, (byte)0xFC, (byte)0x63, (byte)0x25, (byte)0x51
        	};
        	static final byte[] cofactor = { (byte) 0x01};
	}
}


