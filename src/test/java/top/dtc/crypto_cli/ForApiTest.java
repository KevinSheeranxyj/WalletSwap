package top.dtc.crypto_cli;

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import top.dtc.crypto_cli.bip.*;
import top.dtc.crypto_cli.slip.SLIP0044;
import top.dtc.crypto_cli.util.Base58;
import top.dtc.crypto_cli.util.Sha256Hash;
import top.dtc.crypto_cli.wif.WIF;

import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ForApiTest {

    @BeforeAll
    public static void init() {
        BIP0039.init();
    }

    // Test data verified on https://iancoleman.io/bip39/

    @Test
    public void main() throws SignatureException {
//        System.out.println(Base58.encodeChecked(0, BIP.wif(BaseEncoding.base16().decode("142A29AC4D3E73C3FA5625B92D5918943B8674A8CB21BF8716AD47050EDF1110"))));
//        System.out.println(BaseEncoding.base16().encode(BIP.wif(BaseEncoding.base16().decode("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"))));
//        System.out.println(Base58.encode(BIP.wif(BaseEncoding.base16().decode("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"))));
        System.out.println(Base58.encode(BIP.wif(BaseEncoding.base16().decode("142A29AC4D3E73C3FA5625B92D5918943B8674A8CB21BF8716AD47050EDF1110"), true))); // 0-2

        byte[] prvKey = WIF.decode(Base58.decode("cSEjySAREyai8eQhgoqixzmxCeSP8QtbwHxptL8ijofg68ZMjoud")); // From CryptoAPIs document
        System.out.println("Prv: " + BaseEncoding.base16().encode(prvKey));
//        byte[] pubKey = BIP0032.toPublicKeyFromPrivateKey(prvKey);
//        System.out.println(BIP0013.genCompatibilityAddress(pubKey, true));
        System.out.println(Base58.encode(BIP.wif(prvKey, true)));


    }

    /**
     * IMPORTANT: DO NOT USE THESE CREDENTIALS FOR ANY USAGE
     */
    @Test
    public void go() throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] entropy = BaseEncoding.base16().decode("BA43B688194E3651380DDF778D2119EFDF16DAF8F2446117A19CE3A58D1F3790");
        String[] mnemonics = BIP0039.genMnemonics(entropy);
        assertEquals(
                "ripple buffalo pear crater toddler chuckle then room jealous harbor edit text" + " " + "vapor hope toilet embrace genre rug grunt shrug flee moon tattoo black",
                String.join(" ", mnemonics)
        );
        assertArrayEquals(entropy, BIP0039.toBytes(mnemonics));
        byte[] entropyHash = Sha256Hash.hashTwice(entropy);
        String entropyHashStr = Base58.encode(entropyHash).substring(0, 8);
        assertEquals("E5H9UAbq", entropyHashStr);
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

        System.out.println(BaseEncoding.base16().encode(BIP0032.toPublicKeyFromPrivateKey(Base58.decode("L2tTByUZgxqsiC5NQ4tbV2rM8t51j87tSB3EBzw79X47ikL3Aa6v"))));
        System.out.println(BaseEncoding.base16().encode(BIP0032.toPublicKeyFromPrivateKey(BaseEncoding.base16().decode("A966EB6058F8EC9F47074A2FAADD3DAB42E2C60ED05BC34D39D6C0E1D32B8BDF"))));
        System.out.println(BaseEncoding.base16().encode(BIP0032.toPublicKey(Base58.decode("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5e4cp9LB"))));

        byte[] xprv_0_0_0_0 = BIP0044.derive(xprv_master, SLIP0044.BTC, 0, true, 0);
        byte[] pub_0_0_0_0 = BIP0032.toPublicKey(BIP0032.genHdPublicKey(xprv_0_0_0_0));
        assertEquals("1u8YwPPFBaVfJRDhiFhx61ZuFvMTFM4y9", BIP0013.genLegacyAddress(pub_0_0_0_0));
        assertEquals("2Mu3rxTqxiX7KMxd4Kww4Ueu1y2fJA8VshU", BIP0013.genCompatibilityAddress(pub_0_0_0_0, true));
        assertEquals("035AEE2CAB7F404D65B7B10364DA8B9184907CF38408806C79B7F3FC56C4ED8790", BaseEncoding.base16().encode(pub_0_0_0_0));
//        assertEquals("KzxrDKaoUF2AyptoT87Aj9zXdoWFvdTMgLdYSy4svZcF84FHxgDi", Base58.encode(BIP.wif(BIP0032.toPrivateKey(xprv_0_0_0_0))));

        byte[] xprv_0_0_0_1 = BIP0044.derive(xprv_master, SLIP0044.BTC, 0, true, 1);
        byte[] pub_0_0_0_1 = BIP0032.toPublicKey(BIP0032.genHdPublicKey(xprv_0_0_0_1));
        assertEquals("1J1EGjY53TP2otXMYiRp1z32uu4hyvYTFW", BIP0013.genLegacyAddress(pub_0_0_0_1));
        assertEquals("031F03992426C2917C3F58365BE6DE30C6A83752DD36112DF377995056A6FFA21F", BaseEncoding.base16().encode(BIP0032.toPublicKey(BIP0032.genHdPublicKey(xprv_0_0_0_1))));
//        assertEquals("L3EzJ6ShHvNrTRaMpoKmmQSy4Raq1h8byAXwMCsYutfM9woNNQc7", Base58.encode(BIP.wif(BIP0032.toPrivateKey(xprv_0_0_0_1))));

        byte[] xprv_60_761273_0_0 = BIP0044.derive(xprv_master, SLIP0044.ETH, 761273, true, 0);
        byte[] xpub_60_761273_0_0 = BIP0032.genHdPublicKey(xprv_60_761273_0_0);
        byte[] pub_60_761273_0_0 = BIP0032.toPublicKey(xpub_60_761273_0_0);
        byte[] prv_60_761273_0_0 = BIP0032.toPrivateKey(xprv_60_761273_0_0);
        assertEquals("xpub6FsM36iUKuQBkcnKpNy84yAE92hqAqiruFqDpPMALj1gMu9auS3wjjFR1moGApANA4jdXzZ6eZ1vGHhpwNUyvkiPudz9gVN7UdyUpFW7RGM", Base58.encode(xpub_60_761273_0_0));
        assertEquals("1Dd1YEtn5V7TwgzAkJPX4NXM4MSrMniKDP", BIP0013.genLegacyAddress(pub_60_761273_0_0));
        assertEquals("02FBADA42F5B6BCB8CAFFA188FD544D205B87D588246BE076CCBA7EB845BC26FDF", BaseEncoding.base16().encode(pub_60_761273_0_0));
//        assertEquals("Kyf6TjEZoBffTyEThFzLy5pEwoRepsNEjGupC5ThNjhjLPiuaU4i", Base58.encode(BIP.wif(BIP0032.toPrivateKey(xprv_60_761273_0_0))));
        assertEquals("48BBBB76F8E5A972BCCAB9DBA833361211D9F51F1AB33566CFE6D2097CFD4DC0", BaseEncoding.base16().encode(prv_60_761273_0_0));

        byte[] xprv_60_761273_0_516717 = BIP0044.derive(xprv_master, SLIP0044.ETH, 761273, true, 516717);
        byte[] xpub_60_761273_0_516717 = BIP0032.genHdPublicKey(xprv_60_761273_0_516717);
        byte[] pub_60_761273_0_516717 = BIP0032.toPublicKey(BIP0032.genHdPublicKey(xprv_60_761273_0_516717));
        byte[] prv_60_761273_0_516717 = BIP0032.toPrivateKey(xprv_60_761273_0_516717);
        assertEquals("xpub6FsM36iUL29gJe1oBZK14B7HKQjuDYHmTsPMNiBYS4BU5e6gis55mi7H81xNkay1hh47b9y1H1x5NCwEZECDHevZbykoG3DyWvcXbEMBue4", Base58.encode(xpub_60_761273_0_516717));
        assertEquals("1J1rdzh8AyAE9f3JA19QVjLqCgzazsoMP", BIP0013.genLegacyAddress(pub_60_761273_0_516717));
        assertEquals("0360D38882F743C490AA9A825882BB83045A84753A3E52047BFC7C159F582FFA64", BaseEncoding.base16().encode(pub_60_761273_0_516717));
//        assertEquals("KycGaonAshyFZZqCCDtANezFHEq9Wxgae1vmNgMBSmB1yUkgimte", Base58.encode(BIP.wif(prv_60_761273_0_516717)));
        assertEquals("4747A098B03A770201CA2819EA5DDA99CC7A06ED6F364050DD97D56C3E139EE2", BaseEncoding.base16().encode(prv_60_761273_0_516717));

        byte[] xprv_60_123_0_0 = BIP0044.derive(xprv_master, SLIP0044.ETH, 123, true, 0);
        byte[] prv_60_123_0_0 = BIP0032.toPrivateKey(xprv_60_123_0_0);
        assertEquals("3A13A45CEF13FADD19655D5ED0C91E421C4D47A4A3E7A04D9BEADF0EEF7AA492", BaseEncoding.base16().encode(prv_60_123_0_0));

        byte[] xprv_196_761273_0_0 = BIP0044.derive(xprv_master, SLIP0044.TRX + 1, 761273, true, 0);
        byte[] xpub_196_761273_0_0 = BIP0032.genHdPublicKey(xprv_196_761273_0_0);
        byte[] pub_196_761273_0_0 = BIP0032.toPublicKey(xpub_196_761273_0_0);
        byte[] prv_196_761273_0_0 = BIP0032.toPrivateKey(xprv_196_761273_0_0);
        assertEquals("xpub6GoVdEf6PMAqdj62CQX2JaeGyxPXzFGqDh1sGzNwuKa8WNT2Q1mLr9LSTgYhi3iQDBapKdaDUPohM89bQiVQJicQw6Pj8wR99H4xjmvocPn", Base58.encode(xpub_196_761273_0_0));
        assertEquals("16KvpA4BdujLqb4qvrpokpnXYKn7iis3Ld", BIP0013.genLegacyAddress(pub_196_761273_0_0));
        assertEquals("0343E67042DF68930ABB17DF52760EAAA4FA6FBCD1519A88489CFD6CEC2ABC8B30", BaseEncoding.base16().encode(pub_196_761273_0_0));
//        assertEquals("KwmcWvs3eKEcnfeHoJZ8Hw2MuuU6CDCFWzT2H5HGffaHFXifdhFf", Base58.encode(BIP.wif(prv_196_761273_0_0)));
        assertEquals("106967E0302F8B26374DD383CE17F28DA718DC1706D8334D43A5979CC1C41F4B", BaseEncoding.base16().encode(prv_196_761273_0_0));

        byte[] xprv_196_761273_0_516717 = BIP0044.derive(xprv_master, SLIP0044.TRX + 1, 761273, true, 516717);
        byte[] xpub_196_761273_0_516717 = BIP0032.genHdPublicKey(xprv_196_761273_0_516717);
        byte[] pub_196_761273_0_516717 = BIP0032.toPublicKey(xpub_196_761273_0_516717);
        byte[] prv_196_761273_0_516717 = BIP0032.toPrivateKey(xprv_196_761273_0_516717);
        assertEquals("xpub6GoVdEf6PTvL9mwAETj4L6DAictCVFVAziLYA6sxAHv5resw9gP6S5a8iALfAXomprPa4mktJTzuXo7C7bExRh5A1EcPDzf7e5qUsVzYhTp", Base58.encode(xpub_196_761273_0_516717));
        assertEquals("1PUvLftcH5BB92qZsN1PG6VtCCh4hgp8UA", BIP0013.genLegacyAddress(pub_196_761273_0_516717));
        assertEquals("03FCD7DB3BC0556A3E4B9455D0DA34D041A1841B1E0743FF096347137841C1D552", BaseEncoding.base16().encode(pub_196_761273_0_516717));
//        assertEquals("L4vDVKWMW83rdfjxxSkCf1FDv4CnXgKziHKzgEXrXkDeRSEV1a8E", Base58.encode(BIP.wif(prv_196_761273_0_516717)));
        assertEquals("E5B2FF7C80F9D50AE33CD67CE7A6EDD604FCF6A0EA98CC52E2955E79601B05C1", BaseEncoding.base16().encode(prv_196_761273_0_516717));
    }

}
