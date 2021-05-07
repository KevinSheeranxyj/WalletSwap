package top.dtc.crypto_cli.util;

import com.google.common.primitives.Bytes;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.Arrays;

public class Sha256Hash {

    public static byte[] hashWithCheck(byte[] input) {
        byte[] hash = Sha256Hash.hashTwice(input);
        byte[] fingerprint = Arrays.copyOf(hash, 4);
        return Bytes.concat(input, fingerprint);
    }

    public static byte[] hashTwice(byte[] input) {
        return DigestUtils.sha256(DigestUtils.sha256(input));
    }

    public static byte[] hashTwice(byte[] input, int offset, int length) {
        return DigestUtils.sha256(DigestUtils.sha256(Arrays.copyOfRange(input, offset, offset + length)));
    }

}
