package top.dtc.crypto_cli.bip;


import top.dtc.crypto_cli.util.Base58;

public class BIP {

    public String mnemonicsToExtendedPublicKey(
            String mnemonics,
            int coinType,
            int account,
            boolean external,
            int addressIndex
    ) {
        return mnemonicsToExtendedPublicKey(
                mnemonics.split("\\s"),
                coinType,
                account,
                external,
                addressIndex
        );
    }

    public String mnemonicsToExtendedPublicKey(
            String[] mnemonics,
            int coinType,
            int account,
            boolean external,
            int addressIndex
    ) {
        byte[] seed = BIP0039.toBytes(mnemonics);
        byte[] bytes = BIP0044.derive(seed, coinType, account, external, addressIndex);
        return Base58.encode(bytes);
    }

}
