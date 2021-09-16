package top.dtc.crypto_cli.wif;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import top.dtc.crypto_cli.bip.BIP0178;
import top.dtc.crypto_cli.util.Sha256Hash;

import java.security.SignatureException;
import java.util.Arrays;

public class WIF {

    private static final byte[] PREFIX_MAINNET = new byte[] {(byte) 0x80};
    private static final byte[] PREFIX_TESTNET = new byte[] {(byte) 0xEF};

    public static byte[] encode(byte[] input, boolean testnet) {
        byte[] bytes = Bytes.concat(testnet ? PREFIX_TESTNET : PREFIX_MAINNET, input, BIP0178.SPEC.P2PKH_COMPRESSED);
        return Sha256Hash.appendFingerprint(bytes);
    }

    public static byte[] decode(byte[] wif) throws SignatureException {
        byte[] bytes = Sha256Hash.removeFingerprint(wif);
        if (bytes != null) {
            return Arrays.copyOfRange(wif, 1, wif.length - 5);
        }
        throw new SignatureException("WIF fingerprint mismatch: " + BaseEncoding.base16().encode(wif));
    }

}
