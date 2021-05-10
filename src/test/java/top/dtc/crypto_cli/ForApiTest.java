package top.dtc.crypto_cli;

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import top.dtc.crypto_cli.bip.BIP0013;
import top.dtc.crypto_cli.bip.BIP0032;
import top.dtc.crypto_cli.bip.BIP0039;
import top.dtc.crypto_cli.bip.BIP0044;
import top.dtc.crypto_cli.util.Base58;
import top.dtc.crypto_cli.wif.WIF;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ForApiTest {

    @BeforeAll
    public static void init() throws IOException {
        BIP0039.init();
    }

    // Test data generated on https://iancoleman.io/bip39/
    @Test
    public void go() throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] entropy = BaseEncoding.base16().decode("BA43B688194E3651380DDF778D2119EFDF16DAF8F2446117A19CE3A58D1F3790");
        String[] mnemonics = BIP0039.genMnemonics(entropy);
        assertEquals(
                "ripple buffalo pear crater toddler chuckle then room jealous harbor edit text vapor hope toilet embrace genre rug grunt shrug flee moon tattoo black",
                String.join(" ", mnemonics)
        );
        assertArrayEquals(entropy, BIP0039.toBytes(mnemonics));
        byte[] seed = BIP0039.genSeed(mnemonics, "mMpc]HXW&:$98;7<");
        assertEquals(
                "873D7C49734A5FF7FBD30953910B0C9A9DD8207DD3D9ADF42491BC362C60386D54C27ABD32E5913CC32EFCAEF1F2FC974376D26A4432DB13F098BC5C4D1B2578",
                BaseEncoding.base16().encode(seed)
        );

        byte[] xprv_master = BIP0032.genHdMasterPrivateKey(seed);
        assertEquals(
                "xprv9s21ZrQH143K32XqXHWhBugLoJsT9wMvQRQq8eevVjtrCYfwxdVHdkUaJbHDSEea843pyBBwk1FoziTRL5TC4JveouQSLJXntzyW8h79Wu6",
                Base58.encode(xprv_master)
        );

        byte[] xprv_0_0_0_0 = BIP0044.derive(xprv_master, 0, 0, true, 0);
        byte[] pub_0_0_0_0 = BIP0032.toPublicKey(BIP0032.genHdPublicKey(xprv_0_0_0_0));
        assertEquals("1u8YwPPFBaVfJRDhiFhx61ZuFvMTFM4y9", Base58.encode(BIP0013.genAddress(pub_0_0_0_0)));
        assertEquals("035AEE2CAB7F404D65B7B10364DA8B9184907CF38408806C79B7F3FC56C4ED8790", BaseEncoding.base16().encode(pub_0_0_0_0));
        assertEquals("KzxrDKaoUF2AyptoT87Aj9zXdoWFvdTMgLdYSy4svZcF84FHxgDi", Base58.encode(WIF.encode(BIP0032.toPrivateKey(xprv_0_0_0_0))));

        byte[] xprv_0_0_0_1 = BIP0044.derive(xprv_master, 0, 0, true, 1);
        byte[] pub_0_0_0_1 = BIP0032.toPublicKey(BIP0032.genHdPublicKey(xprv_0_0_0_1));
        assertEquals("1J1EGjY53TP2otXMYiRp1z32uu4hyvYTFW", Base58.encode(BIP0013.genAddress(pub_0_0_0_1)));
        assertEquals("031F03992426C2917C3F58365BE6DE30C6A83752DD36112DF377995056A6FFA21F", BaseEncoding.base16().encode(BIP0032.toPublicKey(BIP0032.genHdPublicKey(xprv_0_0_0_1))));
        assertEquals("L3EzJ6ShHvNrTRaMpoKmmQSy4Raq1h8byAXwMCsYutfM9woNNQc7", Base58.encode(WIF.encode(BIP0032.toPrivateKey(xprv_0_0_0_1))));

        byte[] xprv_196_761273_0_0 = BIP0044.derive(xprv_master, 196, 761273, true, 0);
        byte[] pub_196_761273_0_0 = BIP0032.toPublicKey(BIP0032.genHdPublicKey(xprv_196_761273_0_0));
        assertEquals("16KvpA4BdujLqb4qvrpokpnXYKn7iis3Ld", Base58.encode(BIP0013.genAddress(pub_196_761273_0_0)));
        assertEquals("0343E67042DF68930ABB17DF52760EAAA4FA6FBCD1519A88489CFD6CEC2ABC8B30", BaseEncoding.base16().encode(pub_196_761273_0_0));
        assertEquals("KwmcWvs3eKEcnfeHoJZ8Hw2MuuU6CDCFWzT2H5HGffaHFXifdhFf", Base58.encode(WIF.encode(BIP0032.toPrivateKey(xprv_196_761273_0_0))));

        byte[] xprv_196_761273_0_516717 = BIP0044.derive(xprv_master, 196, 761273, true, 516717);
        byte[] pub_196_761273_0_516717 = BIP0032.toPublicKey(BIP0032.genHdPublicKey(xprv_196_761273_0_516717));
        assertEquals("1PUvLftcH5BB92qZsN1PG6VtCCh4hgp8UA", Base58.encode(BIP0013.genAddress(pub_196_761273_0_516717)));
        assertEquals("03FCD7DB3BC0556A3E4B9455D0DA34D041A1841B1E0743FF096347137841C1D552", BaseEncoding.base16().encode(pub_196_761273_0_516717));
        assertEquals("L4vDVKWMW83rdfjxxSkCf1FDv4CnXgKziHKzgEXrXkDeRSEV1a8E", Base58.encode(WIF.encode(BIP0032.toPrivateKey(xprv_196_761273_0_516717))));
    }

}
