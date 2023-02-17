# CRYPTO-CLI

## Supported Coin Types

| Coin Type | Symbol | Coin    |
|----------:|--------|---------|
|         0 | BTC    | Bitcoin |
|        60 | ETH    | Ether   |
|       195 | TRX    | Tron    |
|       966 | MATIC  | MATIC   |

Ref: https://github.com/satoshilabs/slips/blob/master/slip-0044.md

## Default Settings
```
Generate BTC? [Y/N]: Y
Generate ETH? [Y/N]: Y
Generate TRX? [Y/N]: Y
Generate MATIC(Polygon)? [Y/N]: Y
Account number start [0...2147483647]: 0
Account number end [0...10000]: 1
Address index start [0...2147483647]: 0
Address index end [0...10000]: 2000
```

## AWS Setup

### DynamoDB Table

```
Name (Sample): xxx-sub-wallet
Primary key: id (String)
```

### KMS

```
Key type: Symmetric
Alias (Sample): xxx-sub-wallet
```

## Usage

### Environment Variables

Save the following information into the file which path is: `{work_dir}/AWS.env`
```
AWS_REGION=ap-southeast-1
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
KMS_CRYPTO_KEY_ID
DYNAMO_DB_SUB_WALLET_TABLE_NAME
```

### Startup

! Do not use IDE to test, command ascii will not work properly.

```shell
mvn clean
mvn package
java -jar target/dtc-crypto-cli-0.1.0-SNAPSHOT-jar-with-dependencies.jar
```
