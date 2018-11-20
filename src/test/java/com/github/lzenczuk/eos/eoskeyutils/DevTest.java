package com.github.lzenczuk.eos.eoskeyutils;

import org.bitcoinj.core.Base58;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

// https://github.com/EOSIO/eosjs-ecc - based on this library

class DevTest {

    @BeforeAll
    static void init(){
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDsA", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        keyGen.initialize(ecSpec, new SecureRandom());

        KeyPair pair = keyGen.generateKeyPair();

        ECPrivateKey ecPrivateKey = (ECPrivateKey)pair.getPrivate();
    }

    @Test
    void stringToPrivateKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {

        //------------------------------------------------------------------------------------------
        // string to big int
        // https://github.com/JonathanCoe/bitseal/blob/master/src/org/bitseal/crypt/KeyConverter.java

        String privString = "5KK2xvHBiKj4v6KopKNcZ1njfV2MFs16KqMibuyXeBc53uJu19B";
        //5dfPS5CKppnELjf99ceP53sf4vSQgTmx3XSPKroDsSMMa6mPxh

        byte[] privBytes = Base58.decode(privString);

        byte[] mainKey = Arrays.copyOfRange(privBytes, 0, privBytes.length - 4);
        byte[] keyChecksum = Arrays.copyOfRange(privBytes, privBytes.length - 4, privBytes.length);

        if(mainKey[0]!=(byte)128){
            throw new IllegalArgumentException("Key not starts with 128");
        }

        byte[] key = Arrays.copyOfRange(mainKey, 1, mainKey.length);

        BigInteger pkBigint = new BigInteger(key);
        if(pkBigint.signum()<1){
            byte[] missingZero = new byte[1];
            missingZero[0] = (byte) 0;

            pkBigint = new BigInteger(ByteUtils.concatenate(missingZero, key));
        }

        //------------------------------------------------------------------------------------------
        // setup

        KeyFactory keyFactory = KeyFactory.getInstance("ECDsA", "BC");
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");

        //------------------------------------------------------------------------------------------
        // big int to private key

        ECCurve curve = params.getCurve();
        java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, params.getSeed());
        java.security.spec.ECParameterSpec params2 = EC5Util.convertSpec(ellipticCurve, params);
        java.security.spec.ECPrivateKeySpec keySpec = new java.security.spec.ECPrivateKeySpec(pkBigint, params2);

        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(keySpec);

        //------------------------------------------------------------------------------------------
        // private key to public key
        // https://stackoverflow.com/questions/42639620/generate-ecpublickey-from-ecprivatekey

        ECPoint Q = params.getG().multiply(ecPrivateKey.getD());
        byte[] publicBytes = Q.getEncoded(false);

        ECPoint point = params.getCurve().decodePoint(publicBytes);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, params);
        ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);

        //------------------------------------------------------------------------------------------
        // public key to string

        byte[] npubBytes = ecPublicKey.getQ().getEncoded(true);

        // List of message digests
        // https://stackoverflow.com/questions/24979557/complete-list-of-messagedigest-available-in-the-jdk

        MessageDigest messageDigest = MessageDigest.getInstance("RIPEMD160");
        byte[] pubKeyChecksum = messageDigest.digest(npubBytes);

        byte[] pubWithChecksum = ByteUtils.concatenate(npubBytes, Arrays.copyOfRange(pubKeyChecksum, 0, 4));

        String publicKeyEOSFormat = "EOS"+Base58.encode(pubWithChecksum);

        assertEquals("EOS5dfPS5CKppnELjf99ceP53sf4vSQgTmx3XSPKroDsSMMa6mPxh", publicKeyEOSFormat);
    }

}
