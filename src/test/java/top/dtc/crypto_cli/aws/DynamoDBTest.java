package top.dtc.crypto_cli.aws;

import com.google.common.collect.Lists;
import top.dtc.crypto_cli.aws.domain.SubWallet;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DynamoDBTest {

    public static void main(String[] args) {
        SubWallet subWallet = new SubWallet();
        subWallet.coinType = 999;
        subWallet.account = 123;
        subWallet.addressIndex = 456;
        subWallet.prvKey = "abcdefghijlkm";
        subWallet.pubKey = "nopqrstuvwxyz";

        DynamoDB.save(Lists.newArrayList(subWallet));

        SubWallet check = DynamoDB.get(subWallet.coinType, subWallet.account, subWallet.addressIndex);

        assertEquals(subWallet.coinType, check.coinType);
        assertEquals(subWallet.account, check.account);
        assertEquals(subWallet.addressIndex, check.addressIndex);
        assertEquals("abcdefghijlkm", check.prvKey);
        assertEquals("nopqrstuvwxyz", check.pubKey);

        System.out.println(1);
    }

}