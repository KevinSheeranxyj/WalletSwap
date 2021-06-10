package top.dtc.crypto_cli;

import com.google.common.base.Strings;
import top.dtc.crypto_cli.bip.BIP0039;
import top.dtc.crypto_cli.util.Base58;
import top.dtc.crypto_cli.util.Sha256Hash;

import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class Application {

    static final Scanner scanner = new Scanner(System.in);
    static final int ENTROPY_LENGTH = 32;
    static final int MNEMONICS_COUNT = 24;
    static final String SEED_PASSPHASE = "DTC";
    static int TIMER = 3; // 0 < TIMER <= 9

    public static void main(String[] args) {
        try {
            select();
        } catch (Exception e) {
            System.out.print("\033[H\033[2J");
            System.out.flush();
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }

    public static void select() throws InterruptedException {
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
        System.out.println("  0) Quit");
        System.out.println();
        System.out.print("Please select method [0-3]: ");

//        String method = scanner.nextLine();
        String method = "2";
        System.out.println();
        System.out.println();

        switch (method) {
            case "0":
                break;
            case "1":
                genMnemonics();
                break;
            case "2":
                deriveWallets();
                break;
            default:
                System.out.println("Wrong input, program will quit");
        }
        System.out.println("Thanks for using");
    }

    private static void genMnemonics() throws InterruptedException {
        // 0-0 Init BIP-39
        BIP0039.init();

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
        String mnemonicsHashStr = Base58.encode(entropyHash).substring(0, 8);

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
        print(mnemonicsHashStr);
    }

    private static void deriveWallets() throws InterruptedException {
        // 0-0 Input rules
        System.out.println("== Input rules ==");
        System.out.println();
        System.out.println("* Use [SPACE] key to separate words");
        System.out.println("* Press [ENTER] to confirm");
        System.out.println();
        System.out.println();

        // 1-0 Input mnemonics related data
        System.out.println("== Please input mnemonics 1st part ==");
        String mnemonicsPart1Str = input();
        System.out.println("== Please input mnemonics 2nd part ==");
        String mnemonicsPart2Str = input();
        System.out.println("== Please input mnemonics hash ==");
        String mnemonicsHashStr = input();

        // 1-1 Test
        if (mnemonicsHashStr.length() != 8) {
            throw new RuntimeException("Invalid mnemonics hash");
        }
        String[] mnemonics = (mnemonicsPart1Str + " " + mnemonicsPart2Str).split(" ");
        if (mnemonics.length != 24) {
            throw new RuntimeException("Invalid mnemonics");
        }
        byte[] entropy = BIP0039.toBytes(mnemonics);
        byte[] entropyHash = Sha256Hash.hashTwice(entropy);
        String mnemonicsHashStrToCheck = Base58.encode(entropyHash).substring(0, 8);
        if (!mnemonicsHashStr.equals(mnemonicsHashStrToCheck)) {
            throw new RuntimeException("Mismatch mnemonics hash");
        }
    }

    private static String input() throws InterruptedException {
        beep();

        String line = scanner.nextLine();
        clearLines(1);
        correctionTape(line.length());
        clearLines(1);
        System.out.println("<HIDDEN>");
        timer();
        return line.trim();
    }

    private static void print(String str) throws InterruptedException {
        String enter = "Please press [ENTER] before stand up";

        beep();

        System.out.println();
        System.out.println(str);
        System.out.println();
        System.out.print(enter);

        scanner.nextLine();

        clearLines(1);
        correctionTape(enter.length());
        clearLines(3);
        correctionTape(str.length());
        clearLines(1);
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

    private static void clearLines(int count) {
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

}
