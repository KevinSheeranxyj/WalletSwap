package top.dtc.crypto_cli.bip;

public class BIP0044 {

    public static byte[] derive (
            byte[] hdMasterPrivateKey,
            int coinType,
            int account,
            boolean external,
            int addressIndex
    ) {
        byte[] purposeBytes = BIP0032.derive(hdMasterPrivateKey, 44, true);
        byte[] coinTypeBytes = BIP0032.derive(purposeBytes, coinType, true);
        byte[] accountBytes = BIP0032.derive(coinTypeBytes, account, true);
        byte[] changeBytes = BIP0032.derive(accountBytes, external ? 0 : 1, false);
        return BIP0032.derive(changeBytes, addressIndex, false);
    }

}
