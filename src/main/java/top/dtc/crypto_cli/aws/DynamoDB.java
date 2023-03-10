package top.dtc.crypto_cli.aws;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchWriteItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.WriteBatch;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;
import top.dtc.crypto_cli.aws.domain.SubWallet;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class DynamoDB {

    private static final String REGION;
    private static final String AWS_ACCESS_KEY_ID;
    private static final String AWS_SECRET_ACCESS_KEY;
    private static final String KMS_KEY_ID_SUB_WALLET;
    private static final String DYNAMO_DB_TABLE_NAME_SUB_WALLET;

    static {
        Map<String, String> map = new HashMap<>();
        try {
            map = Files.readAllLines(Paths.get("AWS.env")).stream()
                    .map(line -> line.split("="))
                    .collect(Collectors.toMap(seg -> seg[0], seg -> seg[1]));
        } catch (IOException e) {
            e.printStackTrace();

            System.out.println();
            System.out.println("!! Env-vars file ({work_dir}/AWS.env) read failed, program will exit");
            System.exit(-1);
        }
        REGION = map.get("AWS_REGION");
        AWS_ACCESS_KEY_ID = map.get("AWS_ACCESS_KEY_ID");
        AWS_SECRET_ACCESS_KEY = map.get("AWS_SECRET_ACCESS_KEY");
        KMS_KEY_ID_SUB_WALLET = map.get("KMS_KEY_ID_SUB_WALLET");
        DYNAMO_DB_TABLE_NAME_SUB_WALLET = map.get("DYNAMO_DB_TABLE_NAME_SUB_WALLET");
    }

    private static final AwsBasicCredentials awsBasicCredentials = AwsBasicCredentials.create(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY);
    private static final AwsCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(awsBasicCredentials);

    private static final KmsClient kmsClient = KmsClient
            .builder()
            .region(Region.of(REGION))
            .credentialsProvider(credentialsProvider)
            .build();
    private static final DynamoDbClient dynamoDbClient = DynamoDbClient
            .builder()
            .region(Region.of(REGION))
            .credentialsProvider(credentialsProvider)
            .build();
    private static final DynamoDbEnhancedClient enhancedClient = DynamoDbEnhancedClient
            .builder()
            .dynamoDbClient(dynamoDbClient)
            .build();
    private static final DynamoDbTable<SubWallet> table = enhancedClient.table(DYNAMO_DB_TABLE_NAME_SUB_WALLET, TableSchema.fromBean(SubWallet.class));

    public static void printAndTest() {
        System.out.println("AWS_REGION=" + REGION + "\n" +
                "AWS_ACCESS_KEY_ID=" + AWS_ACCESS_KEY_ID + "\n" +
                "AWS_SECRET_ACCESS_KEY=" + (AWS_SECRET_ACCESS_KEY == null ? null : Strings.repeat("*", AWS_SECRET_ACCESS_KEY.length())) + "\n" +
                "KMS_KEY_ID_SUB_WALLET=" + (KMS_KEY_ID_SUB_WALLET == null ? null : Strings.repeat("*", KMS_KEY_ID_SUB_WALLET.length())) + "\n" +
                "DYNAMO_DB_TABLE_NAME_SUB_WALLET=" + DYNAMO_DB_TABLE_NAME_SUB_WALLET);

        try {
            Key key = Key.builder()
                    .partitionValue(id(0, 0, 0))
                    .build();
            SubWallet item = table.getItem(key);
        } catch (Exception e) {
            e.printStackTrace();

            System.out.println();
            System.out.println("!! AWS DynamoDB test failed, program will exit");
            System.exit(-1);
        }
        try {
            encrypt("test");
        } catch (Exception e) {
            e.printStackTrace();

            System.out.println();
            System.out.println("!! AWS KMS test failed, program will exit");
            System.exit(-1);
        }

        System.out.println();
        System.out.println("AWS Functions test successful");
    }

    public static void save(List<SubWallet> subWallets) throws ExecutionException, InterruptedException {
        AtomicInteger i = new AtomicInteger();
        List<List<SubWallet>> lists = Lists.partition(subWallets, 20);
        ForkJoinPool customThreadPool = new ForkJoinPool(10);
        customThreadPool.submit(() ->
                lists.forEach(list -> {
                    System.out.println("Encrypting & uploading partition " + i.incrementAndGet() + " / " + lists.size());
                    WriteBatch.Builder<SubWallet> writeBatchBuilder = WriteBatch
                            .builder(SubWallet.class)
                            .mappedTableResource(table);

                    list.forEach(subWallet -> {
                        subWallet.id = id(subWallet.coinType, subWallet.account, subWallet.addressIndex);
                        subWallet.prvKey = encrypt(subWallet.prvKey);
                        subWallet.pubKey = encrypt(subWallet.pubKey);
                        writeBatchBuilder.addPutItem(subWallet);
                    });

                    BatchWriteItemEnhancedRequest batchWriteItemEnhancedRequest = BatchWriteItemEnhancedRequest
                            .builder()
                            .writeBatches(writeBatchBuilder.build())
                            .build();
                    enhancedClient.batchWriteItem(batchWriteItemEnhancedRequest);

                    try {
                        Thread.sleep(10000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                })
        ).get();
        customThreadPool.shutdown();
    }

    public static SubWallet get(int coinType, int account, int addressIndex) {
        Key key = Key.builder()
                .partitionValue(id(coinType, account, addressIndex))
                .build();

        SubWallet item = table.getItem(key);
        item.prvKey = decrypt(item.prvKey);
        item.pubKey = decrypt(item.pubKey);

        return item;
    }

    private static String encrypt(String data) {
        SdkBytes myBytes = SdkBytes.fromUtf8String(data);
        EncryptRequest encryptRequest = EncryptRequest
                .builder()
                .encryptionAlgorithm(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT)
                .keyId(KMS_KEY_ID_SUB_WALLET)
                .plaintext(myBytes)
                .build();
        EncryptResponse response = kmsClient.encrypt(encryptRequest);
        SdkBytes encryptedData = response.ciphertextBlob();
        return BaseEncoding.base64().encode(encryptedData.asByteArray());
    }

    private static String decrypt(String data) {
        SdkBytes sdkBytes = SdkBytes.fromByteArray(BaseEncoding.base64().decode(data));
        DecryptRequest decryptRequest = DecryptRequest
                .builder()
                .keyId(KMS_KEY_ID_SUB_WALLET)
                .ciphertextBlob(sdkBytes)
                .build();
        DecryptResponse response = kmsClient.decrypt(decryptRequest);
        SdkBytes plaintext = response.plaintext();
        return plaintext.asUtf8String();
    }

    private static String id(int coinType, int account, int addressIndex) {
        return String.format("%d_%d_%d", coinType, account, addressIndex);
    }

}
