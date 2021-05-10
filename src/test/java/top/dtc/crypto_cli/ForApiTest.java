package top.dtc.crypto_cli;

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import top.dtc.crypto_cli.bip.BIP0032;
import top.dtc.crypto_cli.bip.BIP0039;
import top.dtc.crypto_cli.bip.BIP0044;
import top.dtc.crypto_cli.util.Base58;
import top.dtc.crypto_cli.wif.WIF;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class ForApiTest {

    @BeforeAll
    public static void init() throws IOException {
        BIP0039.init();
    }

    @Test
    public void go() throws NoSuchAlgorithmException, InvalidKeySpecException {
//        byte[] entropy = new byte[32];
//        new Random().nextBytes(entropy);
        byte[] entropy = BaseEncoding.base16().decode("BA43B688194E3651380DDF778D2119EFDF16DAF8F2446117A19CE3A58D1F3790");
        System.out.println(BaseEncoding.base16().encode(entropy));
        String[] mnemonics = BIP0039.genMnemonics(entropy);
        System.out.println(String.join(" ", mnemonics));
        assertArrayEquals(entropy, BIP0039.toBytes(mnemonics));
        byte[] seed = BIP0039.genSeed(mnemonics, "mMpc]HXW&:$98;7<");
        System.out.println(BaseEncoding.base16().encode(seed));

        System.out.println();
        byte[] xprv_master = BIP0032.genHdMasterPrivateKey(seed);
        System.out.println(Base58.encode(xprv_master));

        System.out.println();
        byte[] xprv_0_0_0_0 = BIP0044.derive(xprv_master, 0, 0, true, 0);
        System.out.println(BaseEncoding.base16().encode(BIP0032.toPublicKey(BIP0032.genHdPublicKey(xprv_0_0_0_0))));
        System.out.println(Base58.encode(WIF.encode(BIP0032.toPrivateKey(xprv_0_0_0_0))));

        System.out.println();
        byte[] xprv_0_0_0_1 = BIP0044.derive(xprv_master, 0, 0, true, 1);
        System.out.println(BaseEncoding.base16().encode(BIP0032.toPublicKey(BIP0032.genHdPublicKey(xprv_0_0_0_1))));
        System.out.println(Base58.encode(WIF.encode(BIP0032.toPrivateKey(xprv_0_0_0_1))));
    }

}
