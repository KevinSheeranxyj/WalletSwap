package top.dtc.crypto_cli.aws;

import com.google.common.collect.Iterators;
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
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import top.dtc.crypto_cli.aws.domain.SubWallet;

import java.util.List;

public class DynamoDB {

    private static final String KMS_KEY_ID = System.getenv("AWS_KMS_KEY_ID");
    private static final String REGION = System.getenv("AWS_REGION");
    private static final String ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID");
    private static final String SECRET_ACCESS_KEY = System.getenv("AWS_SECRET_ACCESS_KEY");

    private static final AwsBasicCredentials awsBasicCredentials = AwsBasicCredentials.create(ACCESS_KEY_ID, SECRET_ACCESS_KEY);
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
    private static final DynamoDbTable<SubWallet> table = enhancedClient.table("SubWallet", TableSchema.fromBean(SubWallet.class));

    public static void save(List<SubWallet> subWallets) {
        Iterators.partition(subWallets.iterator(), 20).forEachRemaining(list -> {
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
        });
    }

    public static SubWallet get(int coinType, int account, int addressIndex) {
        Key key = Key.builder()
                .partitionValue(id(999, 123, 456))
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
                .keyId(KMS_KEY_ID)
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
                .keyId(KMS_KEY_ID)
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
