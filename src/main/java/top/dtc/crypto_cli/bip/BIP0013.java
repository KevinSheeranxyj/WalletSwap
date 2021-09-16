package top.dtc.crypto_cli.bip;

import com.google.common.io.BaseEncoding;
import top.dtc.crypto_cli.util.Base58;
import top.dtc.crypto_cli.util.Hash160;

public class BIP0013 {

    public static String genCompatibilityAddress(byte[] publicKey, boolean testnet) { // Starts with 3
        return Base58.encodeChecked(testnet ? 0xC4 : 0x05, Hash160.hash(BaseEncoding.base16().decode("0014" + BaseEncoding.base16().encode(Hash160.hash(publicKey)))));
    }

    public static String genLegacyAddress(byte[] publicKey) { // Starts with 1
        return Base58.encodeChecked(0, Hash160.hash(publicKey));
    }

}
