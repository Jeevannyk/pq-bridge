package bank.cards;

import java.security.*;
import javax.crypto.*;

public class KeyService {
    // uses RSA today; see migration ticket CRY-112
    public KeyPair cardKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public byte[] signAuth(PrivateKey k, byte[] msg) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(k);
        s.update(msg);
        return s.sign();
    }

    public byte[] agree(PrivateKey mine, PublicKey theirs) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(mine);
        ka.doPhase(theirs, true);
        return ka.generateSecret();
    }

    public Cipher dataCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
