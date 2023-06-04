package org.knu.cryptography.dsa;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

public class DSA {

    private static final BigInteger ONE = BigInteger.ONE;

    private BigInteger p, q, g, privateKey, publicKey;

    public DSA() throws NoSuchAlgorithmException, InvalidKeySpecException {
        initializeParameters();
    }

    private void initializeParameters() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(1024, random);

        KeyPair pair = keyGen.generateKeyPair();
        DSAPrivateKey priv = (DSAPrivateKey)pair.getPrivate();
        DSAPublicKey pub = (DSAPublicKey)pair.getPublic();

        privateKey = priv.getX();
        publicKey = pub.getY();

        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        DSAPrivateKeySpec privSpec = keyFactory.getKeySpec(priv, DSAPrivateKeySpec.class);
        p = privSpec.getP();
        q = privSpec.getQ();
        g = privSpec.getG();
    }

    public BigInteger[] sign(BigInteger message) {
        BigInteger k, r, s = BigInteger.ZERO;
        Random rnd = new Random();

        do {
            do {
                k = new BigInteger(160, rnd).mod(q.subtract(ONE)).add(ONE);
                r = g.modPow(k, p).mod(q);
            } while (r.equals(BigInteger.ZERO));

            try {
                s = (k.modInverse(q).multiply(message.add(privateKey.multiply(r)))).mod(q);
            } catch (ArithmeticException ignored) { }

        } while (s.equals(BigInteger.ZERO));

        return new BigInteger[]{r, s};
    }

    public boolean verify(BigInteger message, BigInteger[] signature) {
        BigInteger w, u1, u2, v;
        BigInteger r = signature[0], s = signature[1];

        if (r.compareTo(ONE) < 0 || r.compareTo(q) >= 0)
            return false;
        if (s.compareTo(ONE) < 0 || s.compareTo(q) >= 0)
            return false;

        w = s.modInverse(q);
        u1 = (message.multiply(w)).mod(q);
        u2 = (r.multiply(w)).mod(q);
        v = (g.modPow(u1, p).multiply(publicKey.modPow(u2, p)).mod(p)).mod(q);

        return v.equals(r);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //test case for DSA algorithm implementation
        DSA dsa = new DSA();
        BigInteger message = new BigInteger("12345678901234567890");
        BigInteger[] signature = dsa.sign(message);
        System.out.println("Signature: " + signature[0] + ", " + signature[1]);
        boolean verifies = dsa.verify(message, signature);
        System.out.println("Signature verifies: " + verifies);

        BigInteger message2 = new BigInteger("98765432109876543210");
        verifies = dsa.verify(message2, signature);
        System.out.println("Signature verifies with different message: " + verifies);
    }
}
