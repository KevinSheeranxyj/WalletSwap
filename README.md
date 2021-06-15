# DTC-CRYPTO-CLI

## Supported Coin Types

| Coin Type | Symbol | Coin    |
|----------:|--------|---------|
|         0 | BTC    | Bitcoin |
|        60 | ETH    | Ether   |
|       195 | TRX    | Tron    |

Ref: https://github.com/satoshilabs/slips/blob/master/slip-0044.md

## Usage

### System Environment Variables

```
AWS_KMS_KEY_ID
AWS_REGION
ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
```

### Startup

! Do not use IDE to test, command ascii will not work properly.

```shell
mvn clean
mvn package
java -jar target/dtc-crypto-cli-0.1.0-SNAPSHOT-jar-with-dependencies.jar
```
