package top.dtc.crypto_cli.wif;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import top.dtc.crypto_cli.util.Sha256Hash;

import java.security.SignatureException;
import java.util.Arrays;

public class WIF {

    public static byte[] encode(byte[] privateKey) {
        byte[] bytes = Bytes.concat(new byte[] {(byte) 0x80}, privateKey, new byte[] {(byte) 0x01});
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
