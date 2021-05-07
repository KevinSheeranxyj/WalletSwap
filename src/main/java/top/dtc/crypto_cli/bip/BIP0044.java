package top.dtc.crypto_cli.bip;

public class BIP0044 {

    public static byte[] gen(
            byte[] seed,
            int coinType,
            int account,
            boolean external,
            int addressIndex
    ) {
        byte[] mPrvBytes = BIP0032.genHdMasterPrivateKey(seed);
        byte[] purposeBytes = BIP0032.derive(mPrvBytes, 44, true);
        byte[] coinTypeBytes = BIP0032.derive(purposeBytes, coinType, true);
        byte[] accountBytes = BIP0032.derive(coinTypeBytes, account, true);
        byte[] changeBytes = BIP0032.derive(accountBytes, external ? 0 : 1, false);
        return BIP0032.derive(changeBytes, addressIndex, false);
    }

}
