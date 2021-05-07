package top.dtc.crypto_cli.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;

public class Hash160 {

    public static byte[] hash(byte[] bytes) {
        bytes = DigestUtils.sha256(bytes);
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(bytes, 0, bytes.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

}
