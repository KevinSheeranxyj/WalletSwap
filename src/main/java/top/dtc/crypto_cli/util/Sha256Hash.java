package top.dtc.crypto_cli.util;

import com.google.common.primitives.Bytes;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.Arrays;

public class Sha256Hash {

    public static byte[] appendFingerprint(byte[] input) {
        return Bytes.concat(input, genFingerprint(input));
    }

    public static byte[] removeFingerprint(byte[] input) {
        byte[] bytes = Arrays.copyOf(input, input.length - 4);
        byte[] fingerprint = Arrays.copyOfRange(input, input.length - 4, input.length);
        byte[] fingerprintToCheck = genFingerprint(bytes);
        if (Arrays.equals(fingerprint, fingerprintToCheck)) {
            return bytes;
        }
        return null;
    }

    public static byte[] genFingerprint(byte[] input) {
        byte[] hash = Sha256Hash.hashTwice(input);
        return Arrays.copyOf(hash, 4);
    }

    public static byte[] hashTwice(byte[] input) {
        return DigestUtils.sha256(DigestUtils.sha256(input));
    }

    public static byte[] hashTwice(byte[] input, int offset, int length) {
        return DigestUtils.sha256(DigestUtils.sha256(Arrays.copyOfRange(input, offset, offset + length)));
    }

}
