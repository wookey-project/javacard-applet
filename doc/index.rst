.. _javacard:


The JavaCard applets
====================

The WooKey project authentication, DFU and signature tokens are
implemented using JavaCard (https://docs.oracle.com/en/java/javacard/).

JavaCard is a public ecosystem for developing and distributing code
on **secure elements**. Actually, this is one of the only frameworks
allowing to access secure elements without signing NDAs: this makes it
a perfect match for open source projects since the source code can
be distributed.

JavaCard systems (composed of a secure IC and a JavaCard framework) are
usually certified using the EAL Common Criteria scheme: this ensures that
security and penetration tests as well as code review have been performed by entitled ITSEF
(Information Technology Security Evaluation Facility) using a
formal and approved process.

This makes certified JavaCards an interesting choice for hardened components
when designing security solutions: they are robust against a wide variety of
advanced attack scenarios.

For the WooKey project, we have validated our JavaCard applets on an EAL 4+
NXP JCOP J3D081 (https://www.fi.muni.cz/~xsvenda/jcalgtest/run_time/NXPJCOPJ3D081.html).
This JavaCard is dual interface (contact and contacless), is JavaCard 3.0.1 and
GlobalPlatform 2.2 compliant, and is EAL 4+ certified. The public
certification report can be found here:

https://www.commoncriteriaportal.org/files/epfiles/0860b_pdf.pdf

The JCOP J3D081 have been chosen for price and availability reasons.
Please note that the WooKey project applets should be compatible with
**any JavaCard 3.0.1 and above** compatible card!

.. note::
  The WooKey project JavaCard applets do not make use of any proprietary API, and hence
  should be compatible with any JavaCard 3.0.1 and above compatible platform.
  The end user can choose any other secure element of his choice

The JavaCard and GlobalPlatform ecosystems require tools for compiling
as well as pushing the compiled applets (CAP files) to the target.
Fortunately, open source components are available for all these steps.

Compiling can be performed using the ``ant-javacard`` project, with
Oracle SDKs:

https://github.com/martinpaljak/ant-javacard

https://github.com/martinpaljak/oracle_javacard_sdks

Pushing the compiled applets can be done through
the GlobalPlatformPro tool:

https://github.com/martinpaljak/GlobalPlatformPro

.. warning::
  Beware of the GlobalPlatform keys of your product.
  The GlobalPlatformPro tool is aware of public and usual
  default keys of known products, but you must ensure using
  your provider documentation what are your specific GP keys
  (and then feed them to the GlobalPlatformPro tool)

.. danger::
  Do not forget to **lock your token** by changing the GlobalPlatform default keys when
  you have fully configured your token, i.e. when you switch to production mode.
  Changing the keys is **mandatory** for security reasons: if the keys are not modified,
  a malicious user is able to inject rogue applets and break the security model of
  WooKey

.. contents::


Overview
--------

The WooKey project compiles three different applets:

  * The AUTH applet that is used to hold the WooKey platform encryption master key (the AES-CBC-ESSIV key)
  * The DFU applet that is used for Device Firmware Update process when updating a signed and encrypted firmware on the platform
  * The SIG applet that is used on a PC host to encrypt and sign a production firmware

The SIG applet is optional and we offer in the ``menuconfig`` a way to use a passphrase for firmware signature and
encryption. We however strongly advise to use a dedicated token for these operations as such secrets are
very sensitive.

.. danger::
  The SIG applet must be used on a **trusted computer** since it holds the master secrets for firmware signature and
  encryption! It must not be used by a malware as an oracle to sign and encrypt untrusted firmware. It is
  the user's responsibility to ensure that the computer that manipulates sensitive secrets is indeed
  trusted and clean of any potential threat

The three applets authenticate the user using different (Pet Pin, Pet Name, User Pin) triplets, and they
mount a secure channel with the other peer (either the WooKey platform for AUTH and DFU or a host PC for
the SIG token). The secure channel ECDSA keys are diversified for each token.

The JavaCard applets sources are in the 'javacard/applet/src/wookey'
folder, and are organized as follows:

  * The 'common' subfolder contains the code that is shared among all the applets. It mainly contains the cryptographic libraries (for Elliptic Curves ECDSA and ECDH, AES and HMAC), the class handling the secure channel, and the WooKey class that implement the common instructions (i.e. instructions to authenticate the user, handle the Pet Name, mount the secure channel and so on)
  * The 'auth' subfolder contains a 'WooKeyAuth' class implementing the AUTH token specific instructions
  * The 'dfu' subfolder contains a 'WooKeyDFU' class implementing the DFU token specific instructions
  * The 'sig' subfolder contains a 'WooKeySIG' class implementing the SIG token specific instructions

.. danger::
  The computer where the firmware and javacard applets are compiled must be a **trusted computer** since very
  sensitive data is manipulated. It is the user's responsibility to ensure that the computer that manipulates sensitive secrets is indeed
  trusted and clean of any potential threat

In order to select an applet, you must use its AID (Applet ID). Here are the AIDs of the three applets:

  * AUTH AID=45757477747536417070
  * DFU AID=45757477747536417071
  * SIG AID=45757477747536417072

All the applets share the same CLA (class) which is 0x00.


Applets compilation
--------------------

Compiling the applets is as simple as: ::

  $ make javacard_compile

You will need the external dependency ant-javacard compiled or installed, as well
as a 3.0.1 at least JavaCard SDK (3.0.1 or 3.0.3, not above, if you use
a J3D081):

https://github.com/martinpaljak/oracle_javacard_sdks/tree/master/jc303_kit


Applets flash
--------------

Flashing the applets is as simple as connecting a smart card reader to your PC,
and executing: ::

  $ make javacard_push

This supposes that GlobalPlatformPro is compiled or installed, as well as a proper
PC/SC software stack (through packages) to communicate with the smart card reader
and the smart card.

.. warning::
  Depending on your configuration, a message asking you to insert new tokens (with an
  error telling that the applet is already present) might arise. This is related to the
  fact the the menuconfig allows to use the same token or not for the three applet.
  For security reasons, we **strongly advise** to use **three different tokens** for
  these applets!
 

.. note::
  Compiling and flashing can be performed in one operation with ``make javacard``
 

Common instructions in AUTH, DFU, SIG
-------------------------------------

The instructions shared by the three applets are the following: ::

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

The ``TOKEN_INS_SELECT_APPLET`` instruction obviously selects an applet. The ``TOKEN_INS_SECURE_CHANNEL_INIT``
initializes a secure channel between the applet and the peer (WooKey platform or a PC host).
The ``TOKEN_INS_DERIVE_LOCAL_PET_KEY`` derives a keys from a Pet Pin PBKDF2 derived value in
order to decrypt on the peer local keys.

.. warning::
  The token will lock and self-destroy after a configurable number of failed attempts when mounting the secure
  channel with a peer. Beware of this when interacting wit the tokens (the dafault value of number
  of failed attempts is 10)

.. danger::
  Token self-destruction means a permanent loss of sensitive data on the token! (for obvious security
  reasons). It is the user's responsibility to perform key escrow and key recovery (and then proceed to
  flashing a new token or flashing the locked token again). A locked and self-destroyed token can still
  be reflashed/reprogrammed with the proper GP keys

These three instructions are the only ones that are performed **in clear** and **outside the secure channel**.
All the other instructions presented hereafter suppose that (and will check that) the secure channel has
been mounted with the peer.

The ``TOKEN_INS_UNLOCK_PET_PIN`` (resp. ``TOKEN_INS_UNLOCK_USET_PIN``) tries to unlock the Pet Pin (resp. User Pin)
provided in the APDU, and this pin will be locked after a configurable number of failed attempts. Unlocking the
User Pin supposes a previous Pet Pin unlocking.

.. warning::
  The token will lock and self-destroy after a configurable number of failed attempts when presenting the pin
  Beware of this when interacting wit the tokens (the dafault value of number
  of failed attempts is 3)

The ``TOKEN_INS_GET_PET_NAME`` instruction supposes that at least the Pet Pin has been presented, and responds with
the Pet Name stored inside the token.

The ``TOKEN_INS_FULL_LOCK`` fully locks the token (i.e. Pet Pin and User Pin considered as not presented), and
closes the secure channel. The ``TOKEN_INS_USER_PIN_LOCK`` only locks the User Pin (i.e. User Pin considered
as not presented, but Pet Pin considered as presented if it has been successfully presented), and the secure channel
is not closed.

All the following instructions suppose a **full unlocking** of the token (i.e. successful presentation of
the Pet Pin and then the User Pin).

The ``TOKEN_INS_SET_PET_PIN`` (resp. ``TOKEN_INS_SET_USER_PIN``) asks to change the Pet pin (resp. User pin).
These instructions suppose that the user is fully authenticated with the token.

The ``TOKEN_INS_SET_PET_NAME`` modifies the Pet Name sentence that is stored inside the token.

Finally, ``TOKEN_INS_GET_RANDOM`` asks the token for some amount of random bytes, this amount is
encoded on one byte (a maximum size of 224 bytes of random can be asked per instruction).

.. warning::
  The maximum size of the pins (Pet pin and User pin) is 15 bytes, and it is hardcoded. The maximum
  Pet Name length is also hardcoded, and fixed to 64 bytes


AUTH applet
------------

The AUTH applet implements (on top of the common instructions) the following instruction: ::

    /* Instructions specific to the AUTH applet */
    public static final byte TOKEN_INS_GET_KEY = (byte) 0x10;

This instruction supposes that the token is fully unlocked (i.e. Pet pin and User pin
successfully presented by the user) and that the secure channel is properly mounted.
The return value is the 256-bit AES-CBC-ESSIV master key and its hash value.


DFU applet
------------

The DFU applet implements (on top of the common instructions) the following instruction: ::

        /* Instructions specific to the DFU applet */
        public static final byte TOKEN_INS_BEGIN_DECRYPT_SESSION = (byte) 0x20;
        public static final byte TOKEN_INS_DERIVE_KEY = (byte) 0x21;

The ``TOKEN_INS_BEGIN_DECRYPT_SESSION`` opens a firmware decryption session. The instruction
expects a firmware header as input data so that consistency and HMAC of this header is
verified using the token internal secret keys.

The ``TOKEN_INS_DERIVE_KEY`` asks for a key derivation with a sector number on a short (two bytes)
in big endian as input. 

These two instructions are performed in the secure channel and suppose that the token is fully
unlocked (Pet pin and User pin presented correctly).


SIG applet
------------

The SIG applet implements (on top of the common instructions) the following instructions: ::

        public static final byte TOKEN_INS_BEGIN_SIGN_SESSION = (byte) 0x30;
        public static final byte TOKEN_INS_DERIVE_KEY = (byte) 0x31;
        public static final byte TOKEN_INS_SIGN_FIRMWARE = (byte) 0x32;
        public static final byte TOKEN_INS_VERIFY_FIRMWARE = (byte) 0x33;
        public static final byte TOKEN_INS_GET_SIG_TYPE = (byte) 0x34;


``TOKEN_INS_BEGIN_SIGN_SESSION`` opens a firmware signing and encryption session. The instruction
expects a firmware header as input data, computes a HMAC on it using the token internal secret keys and
returns this HMAC as well as an initial random value for firmware encryption session keys.


``TOKEN_INS_DERIVE_KEY`` takes as input a chunk number on two bytes (big endian) and derives
the corresponding encryption key.

``TOKEN_INS_SIGN_FIRMWARE`` signs a hash value of the firmware with the internal ECDSA signature
private key, and ``TOKEN_INS_VERIFY_FIRMWARE`` verifies a signature against a hash value.

.. note::
  Since in JavaCard the usual ECDSA API includes the hash algorithm, a hash value is actually
  signed and verified (i.e. ``ECDSA_SHA256(SHA256(firmware_binary))`` is computed and
  ``SHA256(firmware_binary)`` is sent in the APDU to the token

Finally, ``TOKEN_INS_GET_SIG_TYPE`` returns an encoding of the Elliptic Curve parameters
that the token supports (either BRAINPOOLP256R1, SECP256R1, FRP256V1).

All these instructions are performed in the secure channel and suppose that the token is fully
unlocked (Pet pin and User pin presented correctly).
