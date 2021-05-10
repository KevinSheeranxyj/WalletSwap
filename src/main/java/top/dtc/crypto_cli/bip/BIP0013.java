package top.dtc.crypto_cli.bip;

import com.google.common.primitives.Bytes;
import top.dtc.crypto_cli.util.Hash160;
import top.dtc.crypto_cli.util.Sha256Hash;

public class BIP0013 {

    public static byte[] genAddress(byte[] publicKey) {
        byte[] addressData = Bytes.concat(new byte[] {0x00}, Hash160.hash(publicKey));
        return Bytes.concat(addressData, Sha256Hash.genFingerprint(addressData));
    }

}
