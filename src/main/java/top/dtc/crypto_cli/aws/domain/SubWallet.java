package top.dtc.crypto_cli.aws.domain;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;

@DynamoDbBean
public class SubWallet {

    public Integer coinType;
    public Integer account;
    public Integer addressIndex;
    public String prvKey;
    public String pubKey;

    public Integer getCoinType() {
        return coinType;
    }

    public void setCoinType(Integer coinType) {
        this.coinType = coinType;
    }

    public Integer getAccount() {
        return account;
    }

    public void setAccount(Integer account) {
        this.account = account;
    }

    public Integer getAddressIndex() {
        return addressIndex;
    }

    public void setAddressIndex(Integer addressIndex) {
        this.addressIndex = addressIndex;
    }

    public String getPubKey() {
        return pubKey;
    }

    public void setPubKey(String pubKey) {
        this.pubKey = pubKey;
    }

    public String getPrvKey() {
        return prvKey;
    }

    public void setPrvKey(String prvKey) {
        this.prvKey = prvKey;
    }
}
