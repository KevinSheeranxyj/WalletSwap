package top.dtc.crypto_cli.bip;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import top.dtc.crypto_cli.util.Base58;
import top.dtc.crypto_cli.util.Hash160;
import top.dtc.crypto_cli.util.Sha256Hash;

import java.math.BigInteger;
import java.util.Arrays;

public class BIP0032 {

    public static class VERSION {
        public static final byte[] MAIN_NET_PUBLIC = BaseEncoding.base16().decode("0488B21E");
        public static final byte[] MAIN_NET_PRIVATE = BaseEncoding.base16().decode("0488ADE4");
//        public static final byte[] TEST_NET_PUBLIC = BaseEncoding.base16().decode("043587CF");
//        public static final byte[] TEST_NET_PRIVATE = BaseEncoding.base16().decode("04358394");
    }

    private static final byte[] MASTER_HMAC_KEY = "Bitcoin seed".getBytes();
    private static final ECNamedCurveParameterSpec CURVE = ECNamedCurveTable.getParameterSpec("secp256k1");

    public static byte[] genHdMasterPrivateKey(byte[] seed) {
        byte[] digest = HmacUtils.getInitializedMac(HmacAlgorithms.HMAC_SHA_512, MASTER_HMAC_KEY).doFinal(seed);
        byte[] depth = new byte[] {0x00};
        byte[] parentFingerprint = new byte[] {0x00, 0x00, 0x00, 0x00};
        byte[] childNumber = new byte[] {0x00, 0x00, 0x00, 0x00};
        byte[] chainCode = Arrays.copyOfRange(digest, 32, 64);
        byte[] breakSign = new byte[] {0x00};
        byte[] privateKey = Arrays.copyOfRange(digest, 0, 32);
        byte[] data = Bytes.concat(
                VERSION.MAIN_NET_PRIVATE,
                depth,
                parentFingerprint,
                childNumber,
                chainCode,
                breakSign,
                privateKey
        );
        return Sha256Hash.appendFingerprint(data);
    }

    public static byte[] genHdPublicKey(byte[] hdPrivateKey) {
        byte[] depth = new byte[] {hdPrivateKey[4]};
        byte[] parentFingerprint = Arrays.copyOfRange(hdPrivateKey, 5, 9);
        byte[] childNumber = Arrays.copyOfRange(hdPrivateKey, 9, 13);
        byte[] chainCode = Arrays.copyOfRange(hdPrivateKey, 13, 45);
        byte[] privateKey = Arrays.copyOfRange(hdPrivateKey, 46, 78);
        ECPoint point = CURVE.getG().multiply(new BigInteger(1, privateKey));
        byte[] publicKey = point.getEncoded(true);
        byte[] data = Bytes.concat(
                VERSION.MAIN_NET_PUBLIC,
                depth,
                parentFingerprint,
                childNumber,
                chainCode,
                Arrays.copyOfRange(publicKey, 0, 33)
        );
        return Sha256Hash.appendFingerprint(data);
    }

    public static byte[] derive(byte[] hdPrivateKey, int addressIndex, boolean harden) {
        byte[] depth = new byte[] {(byte) (hdPrivateKey[4] + 1)};
        byte[] childNumber = Ints.toByteArray(harden ? addressIndex | 0x80000000 : addressIndex);
        byte[] parentChainCode = Arrays.copyOfRange(hdPrivateKey, 13, 45);
        byte[] parentPrivateKey = Arrays.copyOfRange(hdPrivateKey, 46, 78);
        ECPoint point = CURVE.getG().multiply(new BigInteger(1, parentPrivateKey));
        byte[] parentPublicKey = point.getEncoded(true);
        byte[] parentFingerprint = Hash160.genFingerprint(parentPublicKey);

        byte[] dataToHash = harden ? Bytes.concat(new byte[] {0x00}, parentPrivateKey, childNumber) : Bytes.concat(parentPublicKey, childNumber);
        byte[] digest = HmacUtils.getInitializedMac(HmacAlgorithms.HMAC_SHA_512, parentChainCode).doFinal(dataToHash);
        byte[] chainCode = Arrays.copyOfRange(digest, 32, 64);
        byte[] breakSign = new byte[] {0x00};
        byte[] privateKey = Arrays.copyOfRange(digest, 0, 32);
        byte[] ki = new BigInteger(1, privateKey).add(new BigInteger(1, parentPrivateKey)).mod(CURVE.getN()).toByteArray();
        Arrays.fill(privateKey, (byte) 0);
        if (ki.length < privateKey.length) {
            System.arraycopy(ki, 0, privateKey, privateKey.length - ki.length, ki.length);
        } else {
            System.arraycopy(ki, ki.length - privateKey.length, privateKey, 0, privateKey.length);
        }
        byte[] data = Bytes.concat(
                VERSION.MAIN_NET_PRIVATE,
                depth,
                parentFingerprint,
                childNumber,
                chainCode,
                breakSign,
                privateKey
        );
        return Sha256Hash.appendFingerprint(data);
    }

    public static byte[] derive(byte[] hdMasterPrivateKey, String path) {
        if (!path.startsWith("m/")) {
            throw new RuntimeException("Wrong path [" + path + "]");
        }
        if (hdMasterPrivateKey[4] != 0) {
            throw new RuntimeException("Not an HD master key");
        }
        byte[] bytes = hdMasterPrivateKey;
        for (String seg : path.substring(2).split("/")) {
            bytes = derive(bytes, Integer.parseInt(seg.endsWith("H") || seg.endsWith("'") ? seg.substring(0, seg.length() - 1) : seg), seg.endsWith("H") || seg.endsWith("'"));
        }
        return bytes;
    }

    public static byte[] toPrivateKey(byte[] hdPrivateKey) {
        return Arrays.copyOfRange(hdPrivateKey, 46, 78);
    }

    public static byte[] toPublicKey(byte[] hdPublicKey) {
        return Arrays.copyOfRange(hdPublicKey, 45, 78);
    }

    public static void main(String[] args) {
        byte[] prv = BaseEncoding.base16().decode("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D");
        ECPoint point = CURVE.getG().multiply(new BigInteger(1, prv));
        byte[] publicKey = point.getEncoded(true);
        System.out.println(BaseEncoding.base16().encode(publicKey));
        System.out.println(BaseEncoding.base16().encode(Base58.decode("KxsBRCHF52joYiQibiQZkFXtDtdYPPqd5BzDWrkphfC6DW2wy9Xq")));

        System.out.println(BaseEncoding.base16().encode(toPrivateKey(Base58.decode("xprv9zZUQ7aGKxuzTxBadprbkUWvBUMyhW4rj7GQcjqdf1d2qtEFQHdsSBgbNNzeLdThhvcUgouVGhQpuGoYHSNy8ifuvSYj6cGDz83ac8pZc1F"))));
        System.out.println(BaseEncoding.base16().encode(toPublicKey(Base58.decode("xpub6DYpod7AALUHgSG3jrPc7cTejWCU6xni6LC1R8FFDMA1igZPwpx7yz15DhAc1qeoax8Q5dvUUdxk4xKPtC5jibAZwXRh7eQKmwPLzBqrDkA"))));
    }

//    public static byte[] genHdPublicKeyBySeed(byte[] seed) {
//        byte[] digest = Hashing.hmacSha512(KEY).hashBytes(seed).asBytes();
//        byte[] depth = new byte[] {0x00};
//        byte[] parentFingerprint = new byte[] {0x00, 0x00, 0x00, 0x00};
//        byte[] childNumber = new byte[] {0x00, 0x00, 0x00, 0x00};
//        byte[] chainCode = Arrays.copyOfRange(digest, 32, 64);
//        byte[] privateKey = Arrays.copyOfRange(digest, 0, 32);
//        ECPoint point = CURVE.getG().multiply(new BigInteger(1, privateKey));
//        byte[] publicKey = point.getEncoded(true);
//        byte[] data = Bytes.concat(
//                VERSION.MAIN_NET_PUBLIC,
//                depth,
//                parentFingerprint,
//                childNumber,
//                chainCode,
//                Arrays.copyOfRange(publicKey, 0, 33)
//        );
//        byte[] hash = Sha256Hash.hashTwice(data);
//        byte[] fingerprint = Arrays.copyOf(hash, 4);
//        return Bytes.concat(data, fingerprint);
//    }

}
