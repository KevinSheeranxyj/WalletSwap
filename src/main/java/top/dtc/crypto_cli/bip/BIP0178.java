package top.dtc.crypto_cli.bip;

public class BIP0178 {

    public static class SPEC {
        public static final byte[] P2PKH_COMPRESSED = new byte[] {(byte) 0x01};
        public static final byte[] P2PKH = new byte[] {(byte) 0x10};
        public static final byte[] P2WPKH = new byte[] {(byte) 0x11};
        public static final byte[] P2WPKH_P2SH = new byte[] {(byte) 0x12};
    }

}
