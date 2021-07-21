package top.dtc.crypto_cli;

import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;
import top.dtc.crypto_cli.aws.DynamoDB;
import top.dtc.crypto_cli.aws.domain.SubWallet;
import top.dtc.crypto_cli.bip.BIP0032;
import top.dtc.crypto_cli.bip.BIP0039;
import top.dtc.crypto_cli.bip.BIP0044;
import top.dtc.crypto_cli.slip.SLIP0044;
import top.dtc.crypto_cli.util.Base58;
import top.dtc.crypto_cli.util.Sha256Hash;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.regex.Pattern;

public class Application {

    static final Scanner scanner = new Scanner(System.in);
    static final Pattern NUMERIC_PATTERN = Pattern.compile("\\d+");

    static final int ENTROPY_LENGTH = 32;
    static final int MNEMONICS_COUNT = 24;
    static final String SEED_PASSPHRASE = "kk^38k^XnV*d";
    static int TIMER = 3; // 0 < TIMER <= 9
    static int BATCH_SIZE = 10000;

    public static void main(String[] args) {
        // Init BIP-39
        BIP0039.init();

        try {
            menu();
        } catch (Exception e) {
            System.out.print("\033[H\033[2J");
            System.out.flush();
            e.printStackTrace();
        } finally {
            scanner.close();
        }
        System.out.println();
        System.out.println("Thanks for using");
    }

    public static void menu() throws InterruptedException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        System.out.println("\n" +
                "                                                                                                                                                               \n" +
                "88888888ba,  888888888888  ,ad8888ba,        ,ad8888ba,   88888888ba  8b        d8  88888888ba  888888888888  ,ad8888ba,         ,ad8888ba,   88           88  \n" +
                "88      `\"8b      88      d8\"'    `\"8b      d8\"'    `\"8b  88      \"8b  Y8,    ,8P   88      \"8b      88      d8\"'    `\"8b       d8\"'    `\"8b  88           88  \n" +
                "88        `8b     88     d8'               d8'            88      ,8P   Y8,  ,8P    88      ,8P      88     d8'        `8b     d8'            88           88  \n" +
                "88         88     88     88                88             88aaaaaa8P'    \"8aa8\"     88aaaaaa8P'      88     88          88     88             88           88  \n" +
                "88         88     88     88                88             88\"\"\"\"88'       `88'      88\"\"\"\"\"\"'        88     88          88     88             88           88  \n" +
                "88         8P     88     Y8,               Y8,            88    `8b        88       88               88     Y8,        ,8P     Y8,            88           88  \n" +
                "88      .a8P      88      Y8a.    .a8P      Y8a.    .a8P  88     `8b       88       88               88      Y8a.    .a8P       Y8a.    .a8P  88           88  \n" +
                "88888888Y\"'       88       `\"Y8888Y\"'        `\"Y8888Y\"'   88      `8b      88       88               88       `\"Y8888Y\"'         `\"Y8888Y\"'   88888888888  88  \n" +
                "                                                                                                                                                               \n" +
                "                                                                                                                                                               \n");

        System.out.println("  1) Generate Mnemonics");
        System.out.println("  2) Derive HD Wallets");
        System.out.println("  3) Test AWS Functions");
        System.out.println("  0) Quit");
        System.out.println();
        int method = intInput("Please select method", 0, 3);

//        String method = scanner.nextLine();
//        String method = "2";
        System.out.println();
        System.out.println();

        switch (method) {
            case 0:
                break;
            case 1:
                genMnemonics();
                break;
            case 2:
                deriveWallets();
                break;
            case 3:
                testAws();
                break;
            default:
                System.out.println("Wrong input, program will quit");
        }
    }

    private static void genMnemonics() throws InterruptedException {
        // 1-0 Generate random entropy
        byte[] entropy = new byte[ENTROPY_LENGTH];
        new Random().nextBytes(entropy);

        // 1-1 Generate mnemonics
        String[] mnemonics = BIP0039.genMnemonics(entropy);

        // 1-2 Entropy hash
        byte[] entropyHash = Sha256Hash.hashTwice(entropy);

        // 1-3 Clear entropy bytes
        Arrays.fill(entropy, (byte) 0);

        // 1-4 Split mnemonics
        String[] mnemonicsPart1 = Arrays.copyOf(mnemonics, MNEMONICS_COUNT / 2);
        String[] mnemonicsPart2 = Arrays.copyOfRange(mnemonics, MNEMONICS_COUNT / 2, MNEMONICS_COUNT);

        // 2-0 Prepare output strings
        String mnemonicsPart1Str = String.join(" ", mnemonicsPart1);
        String mnemonicsPart2Str = String.join(" ", mnemonicsPart2);
        String entropyHashStr = Base58.encode(entropyHash).substring(0, 8);

        // 2-1 Print info
        System.out.println("## Mnemonics will show below ##");
        beep();
        timer();
        System.out.println();

        // 2-2 Print 1st part mnemonics
        System.out.println("== Mnemonics 1st part ==");
        print(mnemonicsPart1Str);

        // 2-3 Print 1st part mnemonics
        System.out.println("== Mnemonics 2nd part ==");
        print(mnemonicsPart2Str);

        // 2-4 Print mnemonics hash
        System.out.println("== Mnemonics hash ==");
        print(entropyHashStr);
    }

    private static void deriveWallets() throws InterruptedException, NoSuchAlgorithmException, InvalidKeySpecException {
        // 0-0 Input rules
        System.out.println("== Input rules ==");
        System.out.println();
        System.out.println("* Use [SPACE] to separate words");
        System.out.println("* Press [ENTER] to confirm");
        System.out.println();
        System.out.println();

        // 1-0 Input mnemonics related data
        System.out.println("== Please input mnemonics 1st part ==");
        String mnemonicsPart1Str = maskedInput();
        System.out.println("== Please input mnemonics 2nd part ==");
        String mnemonicsPart2Str = maskedInput();
        System.out.println("== Please input mnemonics hash ==");
        String mnemonicsHashStr = maskedInput();

        // 1-1 Test & generate entropy
        if (mnemonicsHashStr.length() != 8) {
            throw new RuntimeException("Invalid mnemonics hash");
        }
        String[] mnemonics = (mnemonicsPart1Str + " " + mnemonicsPart2Str).split(" ");
        if (mnemonics.length != 24 || !BIP0039.checkMnemonics(mnemonics)) {
            throw new RuntimeException("Invalid mnemonics");
        }
        byte[] entropy = BIP0039.toBytes(mnemonics);
        byte[] entropyHash = Sha256Hash.hashTwice(entropy);
        String mnemonicsHashStrToCheck = Base58.encode(entropyHash).substring(0, 8);
        if (!mnemonicsHashStr.equals(mnemonicsHashStrToCheck)) {
            throw new RuntimeException("Mismatch mnemonics hash");
        }

        // 2-0 Input coin types and range
        System.out.println("== Please fill these settings ==");
        System.out.println();
        boolean genBtn = booleanInput("Generate BTC?");
        boolean genEth = booleanInput("Generate ETH?");
        boolean genTrx = booleanInput("Generate TRX?");
        if (!genBtn && !genEth && !genTrx) {
            return;
        }
        int accountMin = intInput("Account number start", 0, Integer.MAX_VALUE);
        int accountMax = intInput("Account number end", accountMin, accountMin + BATCH_SIZE);
        int addressIndexMin = intInput("Address index start", 0, Integer.MAX_VALUE);
        int addressIndexMax = intInput("Address index end", addressIndexMin, addressIndexMin + BATCH_SIZE);

        // 2-1 Generate master key
        byte[] seed = BIP0039.genSeed(mnemonics, SEED_PASSPHRASE);
        byte[] xprv_master = BIP0032.genHdMasterPrivateKey(seed);

        List<SubWallet> list = new ArrayList<>();

        if (genBtn) {
            list.addAll(deriveKeys(xprv_master, SLIP0044.BTC, accountMin, accountMax, addressIndexMin, addressIndexMax));
        }
        if (genEth) {
            list.addAll(deriveKeys(xprv_master, SLIP0044.ETH, accountMin, accountMax, addressIndexMin, addressIndexMax));
        }
        if (genTrx) {
            list.addAll(deriveKeys(xprv_master, SLIP0044.TRX, accountMin, accountMax, addressIndexMin, addressIndexMax));
        }

        // 2-2 Cleanup memory data
        mnemonicsPart1Str = null;
        mnemonicsPart2Str = null;
        mnemonicsHashStr = null;
        Arrays.fill(mnemonics, "");
        Arrays.fill(entropy, (byte) 0);
        Arrays.fill(entropyHash, (byte) 0);
        mnemonicsHashStrToCheck = null;
        Arrays.fill(seed, (byte) 0);
        Arrays.fill(xprv_master, (byte) 0);

        // 3-0 Notice before upload

        System.out.println("== Press ENTER to upload");
        beep();
        scanner.nextLine();

        // 3-1 Upload

//        DynamoDB.save(list);

//        // 2-2 Pause
//        beep();
//        System.out.println();
//        System.out.println("Keys generated, press [ENTER] to upload");
//        scanner.nextLine();
//
//        // 3-0 Write to file (TEMPORARY)
//        String userDir = System.getProperty("user.dir");
//        try {
//            Files.writeString(Path.of(userDir, "test.dtc"), result);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//
//        System.out.println();
//        System.out.println();
        System.out.println("Upload successful");
    }

    private static void testAws() {
        System.out.println("== AWS ENVIRONMENT VARIABLES ==");
        DynamoDB.printAndTest();
        System.out.println();
        System.out.println();
    }

    private static String maskedInput() throws InterruptedException {
        beep();

        String line = scanner.nextLine();
        backLines(1);
        correctionTape(line.length());
        backLines(1);
        System.out.println("<HIDDEN>");
        timer();
        return line.trim();
    }

    private static String[] mnemonicsInput() {
        return null;
    }

    private static boolean booleanInput(String label) throws InterruptedException {
        beep();

        System.out.print(label + " [Y/N]: ");
        String result = scanner.nextLine().trim();
        switch (result) {
            case "Y":
            case "y":
                return true;
            case "N":
            case "n":
                return false;
        }
        backLines(1);
        return booleanInput(label);
    }

    private static int intInput(String label, int min, int max) throws InterruptedException {
        beep();

        System.out.print(label + " [" + min + "..." + max + "]: ");
        String result = scanner.nextLine().trim();
        if (NUMERIC_PATTERN.matcher(result).matches()) {
            try {
                int number = Integer.parseInt(result);
                if (number >= min && number <= max) {
                    return number;
                }
            } finally {}
        }
        backLines(1);
        return intInput(label, min, max);
    }

    private static void print(String str) throws InterruptedException {
        String enter = "Please press [ENTER] before stand up";

        beep();

        System.out.println();
        System.out.println(str);
        System.out.println();
        System.out.print(enter);

        scanner.nextLine();

        backLines(1);
        correctionTape(enter.length());
        backLines(3);
        correctionTape(str.length());
        backLines(1);
        System.out.println("<HIDDEN>");
        System.out.println();

        timer();
    }

    private static void beep() throws InterruptedException {
        for (int i = 0; i < 3; i++) {
            System.out.print("\007");
            System.out.flush();
            Thread.sleep(120);
        }
    }

    private static void correctionTape(int length) {
        System.out.println(Strings.repeat(" ", length));
    }

    private static void backLines(int count) {
        System.out.print(String.format("\033[%dA", count));
        System.out.print("\033[2K");
        System.out.flush();
    }

    private static void timer() throws InterruptedException {
        int i = TIMER;
        do {
            System.out.print(i);
            Thread.sleep(1000L);
            System.out.print("\b");
            i--;
        } while (i > 0);
        correctionTape(1);
    }

    private static List<SubWallet> deriveKeys(
            byte[] xprv_master,
            int coinType,
            int accountMin,
            int accountMax,
            int addressIndexMin,
            int addressIndexMax
    ) {
        List<SubWallet> list = new ArrayList<>();
        for (int account = accountMin; account <= accountMax; account++) {
            for (int addressIndex = addressIndexMin; addressIndex <= addressIndexMax; addressIndex++) {
                byte[] xprv = BIP0044.derive(
                        xprv_master,
                        coinType,
                        account,
                        true,
                        addressIndex
                );
                byte[] xpub = BIP0032.genHdPublicKey(xprv);
                byte[] prv = BIP0032.toPrivateKey(xprv);
                byte[] pub = BIP0032.toPublicKey(xpub);

                SubWallet subWallet = new SubWallet();
                subWallet.coinType = coinType;
                subWallet.account = account;
                subWallet.addressIndex = addressIndex;
                subWallet.prvKey = BaseEncoding.base16().encode(prv);
                subWallet.pubKey = BaseEncoding.base16().encode(pub);
                list.add(subWallet);
            }
        }

        return list;
    }

//    private static void deriveKeys(
//            StringBuilder builder,
//            byte[] xprv_master,
//            int coinType,
//            int accountMin,
//            int accountMax,
//            int addressIndexMin,
//            int addressIndexMax
//    ) {
//        for (int account = accountMin; account <= accountMax; account++) {
//            for (int addressIndex = addressIndexMin; addressIndex <= addressIndexMax; addressIndex++) {
//                byte[] xprv = BIP0044.derive(
//                        xprv_master,
//                        coinType,
//                        account,
//                        true,
//                        addressIndex
//                );
//                byte[] xpub = BIP0032.genHdPublicKey(xprv);
//                byte[] prv = BIP0032.toPrivateKey(xprv);
//                byte[] pub = BIP0032.toPublicKey(xpub);
//                String line = String.format(
//                        "%d\t%d\t%d\t%s\t%s",
//                        coinType,
//                        account,
//                        addressIndex,
//                        Base58.encode(prv),
//                        Base58.encode(pub)
//                );
//                builder.append(line).append("\n");
//            }
//        }
//    }

}
