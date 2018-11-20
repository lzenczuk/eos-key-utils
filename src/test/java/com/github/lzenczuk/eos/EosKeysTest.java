package com.github.lzenczuk.eos;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EosKeysTest {

    @BeforeAll
    static void init(){
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void shouldMatchPrivateAndPublicKeys() throws EosKeyExpection {

        String[] privateKeys = {
                "5JXwcv9NyxZi6EVcrBHESu3Y73hyZ69QndmRhTrz244J6JfayjZ",
                "5J8QyAXemysNU8AmG2zfpG4sUMqzQLtXyT49XwpPS9zaEFaVzFp",
                "5Hz5uUUzfNV1R6jVm246L73S7t6aqFaMTFJShCBg29pLieXF5QD",
                "5JHBPSbHyspN8u6WFhUXYbzxvsfGsRnBtqSPuVsKBfwFXNE5Tz4",
                "5JBPWkC5KHBJyg9A2mwdBCysmt5o5wJFcwXF7x2CYnCG2Tg9XWW",
        };

        String[] publicKeys = {
                "EOS8AZyFQWL4Fz9ZB3fr9dpi44EAnt5Xig1NQe8vH6ZCWcBgCbvck",
                "EOS8YJ4VEhWbH3SPppCdZ11cPMnrv3v74PmZSfmV3rnV785gLgLZZ",
                "EOS4ykLuBZmViSC2xxUgFAhLuN8wo2pP2hEuPRsvTHNjxLtMSC5Qb",
                "EOS5u9yossgenAJY1Hnf7n5uZ4abUFLkg2BM8DdCkZwoHstUTkUHM",
                "EOS6qQHwzCrSFn2STDF5LhsJJMzdBAbDQzckN8TQJrzcs51vTnFec",
        };

        for(int i=0; i<privateKeys.length; i++){
            EosPrivateKey eosPrivateKey = new EosPrivateKey(privateKeys[i]);
            EosPublicKey eosPublicKeyFromPrivateKey = eosPrivateKey.getPublicKey();
            EosPublicKey eosPublicKeyFromString = new EosPublicKey(publicKeys[i]);

            assertEquals(publicKeys[i], eosPublicKeyFromPrivateKey.toEosString());
            assertEquals(publicKeys[i], eosPublicKeyFromString.toEosString());
            assertEquals(privateKeys[i], eosPrivateKey.toWif());
        }
    }

    @Test
    void shouldSignAndConfirmSignature() throws EosKeyExpection {

        String[] privateKeys = {
                "5JXwcv9NyxZi6EVcrBHESu3Y73hyZ69QndmRhTrz244J6JfayjZ",
                "5J8QyAXemysNU8AmG2zfpG4sUMqzQLtXyT49XwpPS9zaEFaVzFp",
                "5Hz5uUUzfNV1R6jVm246L73S7t6aqFaMTFJShCBg29pLieXF5QD",
                "5JHBPSbHyspN8u6WFhUXYbzxvsfGsRnBtqSPuVsKBfwFXNE5Tz4",
                "5JBPWkC5KHBJyg9A2mwdBCysmt5o5wJFcwXF7x2CYnCG2Tg9XWW",
        };

        String[] publicKeys = {
                "EOS8AZyFQWL4Fz9ZB3fr9dpi44EAnt5Xig1NQe8vH6ZCWcBgCbvck",
                "EOS8YJ4VEhWbH3SPppCdZ11cPMnrv3v74PmZSfmV3rnV785gLgLZZ",
                "EOS4ykLuBZmViSC2xxUgFAhLuN8wo2pP2hEuPRsvTHNjxLtMSC5Qb",
                "EOS5u9yossgenAJY1Hnf7n5uZ4abUFLkg2BM8DdCkZwoHstUTkUHM",
                "EOS6qQHwzCrSFn2STDF5LhsJJMzdBAbDQzckN8TQJrzcs51vTnFec",
        };

        for(int i=0; i<privateKeys.length; i++){
            EosPrivateKey eosPrivateKey = new EosPrivateKey(privateKeys[i]);
            EosPublicKey eosPublicKey = new EosPublicKey(publicKeys[i]);

            byte[] signature = eosPrivateKey.sign("This is test string");
            assertTrue(eosPublicKey.verifySignature("This is test string", signature));
        }
    }

    @Test
    void shouldSignAndRejectSignature() throws EosKeyExpection {

        String[] privateKeys = {
                "5JBPWkC5KHBJyg9A2mwdBCysmt5o5wJFcwXF7x2CYnCG2Tg9XWW",
                "5JXwcv9NyxZi6EVcrBHESu3Y73hyZ69QndmRhTrz244J6JfayjZ",
                "5J8QyAXemysNU8AmG2zfpG4sUMqzQLtXyT49XwpPS9zaEFaVzFp",
                "5Hz5uUUzfNV1R6jVm246L73S7t6aqFaMTFJShCBg29pLieXF5QD",
                "5JHBPSbHyspN8u6WFhUXYbzxvsfGsRnBtqSPuVsKBfwFXNE5Tz4",
        };

        String[] publicKeys = {
                "EOS8AZyFQWL4Fz9ZB3fr9dpi44EAnt5Xig1NQe8vH6ZCWcBgCbvck",
                "EOS8YJ4VEhWbH3SPppCdZ11cPMnrv3v74PmZSfmV3rnV785gLgLZZ",
                "EOS4ykLuBZmViSC2xxUgFAhLuN8wo2pP2hEuPRsvTHNjxLtMSC5Qb",
                "EOS5u9yossgenAJY1Hnf7n5uZ4abUFLkg2BM8DdCkZwoHstUTkUHM",
                "EOS6qQHwzCrSFn2STDF5LhsJJMzdBAbDQzckN8TQJrzcs51vTnFec",
        };

        for(int i=0; i<privateKeys.length; i++){
            EosPrivateKey eosPrivateKey = new EosPrivateKey(privateKeys[i]);
            EosPublicKey eosPublicKey = new EosPublicKey(publicKeys[i]);

            byte[] signature = eosPrivateKey.sign("This is test string");
            assertFalse(eosPublicKey.verifySignature("This is test string", signature));
        }
    }

}
