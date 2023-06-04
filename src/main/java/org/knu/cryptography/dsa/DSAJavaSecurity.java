package org.knu.cryptography.dsa;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class DSAJavaSecurity {

    public static void main(String[] args) throws Exception {
        //test case for DSA algorithm implementation using java library tools
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
        dsa.initSign(priv);
        String str = "This is a string to sign";
        byte[] strByte = str.getBytes(StandardCharsets.UTF_8);
        dsa.update(strByte);
        byte[] realSig = dsa.sign();

        System.out.println("Signature: " + Base64.getEncoder().encodeToString(realSig));

        dsa.initVerify(pub);
        dsa.update(strByte);
        boolean verifies = dsa.verify(realSig);
        System.out.println("Signature verifies: " + verifies);
    }
}
