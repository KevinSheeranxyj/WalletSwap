package top.dtc.crypto_cli.bip;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.stream.Collectors;

public final class BIP0039 {

    private static final List<String> ENGLISH_DICT = new ArrayList<>();
    private static final Map<String, Integer> ENGLISH_REV = new HashMap<>();

    private static final String ENGLISH_SHA256 = "ad90bf3beb7b0eb7e5acd74727dc0da96e0a280a258354e7293fb7e211ac03db";

    public static void init() {
        InputStream in = BIP0039.class.getResourceAsStream("/bip-0039/english.txt");
        if (in == null) {
            throw new RuntimeException("Dict file reading failed");
        }
        List<String> lines = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)).lines().collect(Collectors.toList());
        for (int i = 0; i < lines.size(); i++) {
            ENGLISH_DICT.add(lines.get(i));
            ENGLISH_REV.put(lines.get(i), i);
        }
        String hash = DigestUtils.sha256Hex(String.join("", lines));
        if (!ENGLISH_SHA256.equals(hash)) {
            throw new RuntimeException("English Mnemonic checksum failed");
        }
    }

    public static String[] genMnemonics(byte[] entropy) {
        if (entropy.length % 8 != 0 || entropy.length < 16) {
            throw new RuntimeException("Entropy length error: " + entropy.length);
        }
        byte[] hash = DigestUtils.sha256(entropy);
        byte[] bytes = Bytes.concat(entropy, hash);
        int size = (int) Math.ceil((entropy.length * 8 + entropy.length / 4.0) / 11f);
        String[] result = new String[size];
        for (int i = 0; i < size; i++) {
            int shift = (int) ((Math.ceil((i + 1) * 11 / 8.0)) * 8 % 11);
            int start = i * 11 / 8;
            int n;
            if (shift < 6) {
                n = (bytes[start] & 0xFF) << (8 - shift) | (bytes[start + 1] & 0xFF) >> shift;
            } else {
                n = (bytes[start] & 0xFF) << (16 - shift) | (bytes[start + 1] & 0xFF) << (8 - shift) | (bytes[start + 2] & 0xFF) >> shift;
            }
            n &= 0x7FF;
            result[i] = ENGLISH_DICT.get(n);
        }
        return result;
    }

    public static boolean checkMnemonics(String[] mnemonics) {
        for (String mnemonic : mnemonics) {
            if (!ENGLISH_REV.containsKey(mnemonic)) {
                return false;
            }
        }
        return true;
    }

    public static byte[] toBytes(String[] mnemonics) {
        if (mnemonics.length < 6 || mnemonics.length % 3 != 0) {
            throw new RuntimeException("Mnemonics length error: " + mnemonics.length);
        }
        byte[] bytes = new byte[(int) Math.ceil(mnemonics.length * 11 / 8.0)];
        for (int i = 0; i < mnemonics.length; i++) {
            if (!ENGLISH_REV.containsKey(mnemonics[i])) {
                throw new RuntimeException("Mnemonics not found: " + mnemonics[i]);
            }
            int shift = (int) (Math.ceil((i + 1) * 11 / 8.0) * 8 % 11);
            int start = i * 11 / 8;
            byte[] n = Ints.toByteArray(ENGLISH_REV.get(mnemonics[i]) << shift);
            if (shift < 6) {
                bytes[start] |= n[2];
                bytes[start + 1] |= n[3];
            } else {
                bytes[start] |= n[1];
                bytes[start + 1] |= n[2];
                bytes[start + 2] |= n[3];
            }
        }
        int hashSize = mnemonics.length * 11 / 33;
        int hash = (bytes[bytes.length - 1] & 0xFF) >> (8 - hashSize) & 0xFF;
        byte[] entropy = Arrays.copyOfRange(bytes, 0, bytes.length - 1);
        byte[] hashToCheck = DigestUtils.sha256(entropy);
        if ((hashToCheck[0] & 0xFF) >> (8 - hashSize) != hash) {
            throw new RuntimeException("Mnemonics checksum failed");
        }
        return entropy;
    }

    public static byte[] genSeed(String[] mnemonics, String passphrase) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec spec = new PBEKeySpec(String.join(" ", mnemonics).toCharArray(), ("mnemonic" + passphrase).getBytes(), 2048, 512);
        SecretKey key = skf.generateSecret(spec);
        return key.getEncoded();
    }

}
