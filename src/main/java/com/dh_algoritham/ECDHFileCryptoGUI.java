package com.dh_algoritham;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.codec.binary.Base64;

public class ECDHFileCryptoGUI {

    // Generate ECDH shared secret
    public static byte[] generateECDH() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();

        byte[] ourPk = kp.getPublic().getEncoded();
        System.out.println("Public Key (send to other party): " + Base64.encodeBase64String(ourPk));

        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey otherPublicKey = kf.generatePublic(new X509EncodedKeySpec(ourPk));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(otherPublicKey, true);

        byte[] sharedSecret = ka.generateSecret();
        System.out.println("Shared Secret: " + DatatypeConverter.printHexBinary(sharedSecret));

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] aesKey = sha256.digest(sharedSecret);
        return aesKey;
    }

    // Encrypt file with original extension stored
    public static void enc(File inputFile, byte[] sharedSecret, String fileName, JTextArea statusArea, JProgressBar progressBar) throws Exception {
        SecretKeySpec key = new SecretKeySpec(sharedSecret, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] iv = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        // Extract original file extension
        String originalExtension = "";
        String inputFileName = inputFile.getName();
        int lastDotIndex = inputFileName.lastIndexOf('.');
        if (lastDotIndex != -1 && lastDotIndex < inputFileName.length() - 1) {
            originalExtension = inputFileName.substring(lastDotIndex + 1);
        }

        // Encode extension as bytes (prefix with length)
        byte[] extensionBytes = originalExtension.getBytes(StandardCharsets.UTF_8);
        byte[] extensionLength = new byte[]{(byte) extensionBytes.length};

        String outputFileName = fileName + "_" + DatatypeConverter.printHexBinary(sharedSecret) + ".enc";
        File outputDir = new File(System.getProperty("user.dir") + File.separator + "Files");
        if (!outputDir.exists()) {
            if (!outputDir.mkdirs()) {
                throw new IOException("Failed to create directory: " + outputDir.getAbsolutePath());
            }
        }
        File encryptedFile = new File(outputDir, outputFileName);

        statusArea.setText("Encrypting file: " + inputFile.getName() + "...");
        progressBar.setValue(0);

        try (FileOutputStream fos = new FileOutputStream(encryptedFile);
             BufferedOutputStream bos = new BufferedOutputStream(fos);
             FileInputStream fis = new FileInputStream(inputFile);
             BufferedInputStream bis = new BufferedInputStream(fis);
             CipherOutputStream cos = new CipherOutputStream(bos, cipher)) {
            // Write extension length (1 byte), extension, and IV
            bos.write(extensionLength);
            bos.write(extensionBytes);
            bos.write(iv);

            byte[] buffer = new byte[8192];
            int read;
            long totalRead = 0;
            long fileSize = inputFile.length();
            while ((read = bis.read(buffer)) != -1) {
                cos.write(buffer, 0, read);
                totalRead += read;
                if (fileSize > 0) {
                    int progress = (int) ((totalRead * 100) / fileSize);
                    progressBar.setValue(progress);
                    statusArea.setText("Encrypting file: " + inputFile.getName() + " (" + progress + "%)");
                }
            }
        }
        progressBar.setValue(100);
    }

    // Decrypt file and restore original extension
    public static String dec(File encryptedFile, String secretHex, String fileNamePrefix, JTextArea statusArea, JProgressBar progressBar) throws Exception {
        // Validate hex string
        try {
            DatatypeConverter.parseHexBinary(secretHex);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid shared secret format. Please enter a valid hex string.");
        }

        byte[] sharedSecret = DatatypeConverter.parseHexBinary(secretHex);
        SecretKeySpec key = new SecretKeySpec(sharedSecret, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Read extension length, extension, and IV
        byte[] extensionLength = new byte[1];
        byte[] iv = new byte[16];
        String originalExtension;
        int extLength;
        try (FileInputStream fis = new FileInputStream(encryptedFile)) {
            int bytesRead = fis.read(extensionLength);
            if (bytesRead != 1) throw new IOException("Failed to read extension length from encrypted file.");
            extLength = extensionLength[0] & 0xFF;
            if (extLength > 255) throw new IOException("Extension length too large: " + extLength);
            byte[] extensionBytes = new byte[extLength];
            bytesRead = fis.read(extensionBytes);
            if (bytesRead != extLength) throw new IOException("Failed to read extension from encrypted file.");
            originalExtension = new String(extensionBytes, StandardCharsets.UTF_8);
            bytesRead = fis.read(iv);
            if (bytesRead != iv.length) throw new IOException("Failed to read IV from encrypted file.");
        }

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        String outputFileName = fileNamePrefix + "_" + System.currentTimeMillis() + (originalExtension.isEmpty() ? "" : "." + originalExtension);
        File outputDir = new File(System.getProperty("user.dir") + File.separator + "Files" + File.separator + "decFiles");
        if (!outputDir.exists()) {
            if (!outputDir.mkdirs()) {
                throw new IOException("Failed to create directory: " + outputDir.getAbsolutePath());
            }
        }
        File outputFile = new File(outputDir, outputFileName);

        statusArea.setText("Decrypting file: " + encryptedFile.getName() + "...");
        progressBar.setValue(0);

        try (FileInputStream fis = new FileInputStream(encryptedFile);
             BufferedInputStream bis = new BufferedInputStream(fis);
             CipherInputStream cis = new CipherInputStream(bis, cipher);
             FileOutputStream fos = new FileOutputStream(outputFile);
             BufferedOutputStream bos = new BufferedOutputStream(fos)) {
            // Skip extension length (1 byte), extension, and IV
            long bytesToSkip = 1 + extLength + iv.length;
            long skipped = bis.skip(bytesToSkip);
            if (skipped != bytesToSkip) throw new IOException("Failed to skip header in encrypted file.");

            byte[] buffer = new byte[8192];
            int read;
            long totalRead = 0;
            long fileSize = encryptedFile.length();
            while ((read = cis.read(buffer)) != -1) {
                bos.write(buffer, 0, read);
                totalRead += read;
                if (fileSize > 0) {
                    int progress = (int) ((totalRead * 100) / fileSize);
                    progressBar.setValue(progress);
                    statusArea.setText("Decrypting file: " + encryptedFile.getName() + " (" + progress + "%)");
                }
            }
        } catch (Exception e) {
            throw new Exception("Decryption failed: " + e.getMessage(), e);
        }
        progressBar.setValue(100);
        return outputFileName;
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }

        JFrame frame = new JFrame("File Encryption/Decryption");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 450);
        frame.setLocationRelativeTo(null);
        frame.setLayout(new BorderLayout());

        // Gradient panel for background
        JPanel mainPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                GradientPaint gradient = new GradientPaint(0, 0, new Color(204, 201, 201), 0, getHeight(), new Color(202, 203, 204));
                g2d.setPaint(gradient);
                g2d.fillRect(0, 0, getWidth(), getHeight());
            }
        };
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));

        // Title
        JLabel titleLabel = new JLabel("File Encryption/Decryption", SwingConstants.CENTER);
        titleLabel.setFont(new Font("Arial", Font.BOLD, 28));
        titleLabel.setForeground(Color.BLACK);
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Buttons panel
        JPanel buttonPanel = new JPanel();
        buttonPanel.setOpaque(false);
        buttonPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 20, 20));

        JButton encryptButton = new JButton("Encrypt File");
        JButton decryptButton = new JButton("Decrypt File");

        // Style buttons with rounded corners
        encryptButton.setFont(new Font("Arial", Font.BOLD, 16));
        decryptButton.setFont(new Font("Arial", Font.BOLD, 16));
        encryptButton.setBackground(new Color(255, 255, 255));
        decryptButton.setBackground(new Color(255, 255, 255));
        encryptButton.setForeground(new Color(33, 150, 243));
        decryptButton.setForeground(new Color(76, 175, 80));
        encryptButton.setPreferredSize(new Dimension(160, 50));
        decryptButton.setPreferredSize(new Dimension(160, 50));
        encryptButton.setFocusPainted(false);
        decryptButton.setFocusPainted(false);
        encryptButton.setBorder(BorderFactory.createLineBorder(new Color(33, 150, 243), 2, true));
        decryptButton.setBorder(BorderFactory.createLineBorder(new Color(76, 175, 80), 2, true));

        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

        // Progress bar
        JProgressBar progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setForeground(new Color(33, 150, 243));
        progressBar.setBackground(Color.WHITE);
        progressBar.setPreferredSize(new Dimension(500, 25));
        progressBar.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Status area
        JTextArea statusArea = new JTextArea(6, 40);
        statusArea.setEditable(false);
        statusArea.setFont(new Font("Arial", Font.PLAIN, 14));
        statusArea.setLineWrap(true);
        statusArea.setWrapStyleWord(true);
        statusArea.setBackground(new Color(255, 255, 255, 230));
        statusArea.setForeground(Color.BLACK);
        statusArea.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(33, 150, 243), 1, true),
                BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));
        JScrollPane statusScroll = new JScrollPane(statusArea);
        statusScroll.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Add components to main panel
        mainPanel.add(titleLabel);
        mainPanel.add(Box.createVerticalStrut(30));
        mainPanel.add(buttonPanel);
        mainPanel.add(Box.createVerticalStrut(20));
        mainPanel.add(progressBar);
        mainPanel.add(Box.createVerticalStrut(20));
        mainPanel.add(statusScroll);

        frame.add(mainPanel, BorderLayout.CENTER);

        // File chooser
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File(System.getProperty("user.dir")));

        // Encrypt button action
        encryptButton.addActionListener(e -> {
            fileChooser.setDialogTitle("Select File to Encrypt");
            if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                try {
                    File inputFile = fileChooser.getSelectedFile();
                    byte[] sharedSecret = generateECDH();
                    String fileName = "EncryptedFile";
                    enc(inputFile, sharedSecret, fileName, statusArea, progressBar);
                    String secretHex = DatatypeConverter.printHexBinary(sharedSecret);
                    String outputFileName = fileName + "_" + secretHex + ".enc";
                    statusArea.setText("File encrypted successfully.\nShared Secret (save this!):\n" + secretHex +
                            "\nEncrypted file saved in 'Files' directory as " + outputFileName +
                            "\n\nImportant: Copy and save the shared secret exactly as shown above for decryption.");
                } catch (Exception ex) {
                    statusArea.setText("Encryption error: " + ex.getMessage());
                    progressBar.setValue(0);
                    ex.printStackTrace();
                }
            }
        });

        // Decrypt button action
        decryptButton.addActionListener(e -> {
            fileChooser.setDialogTitle("Select File to Decrypt");
            if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                String secretHex = JOptionPane.showInputDialog(frame, "Enter Shared Secret (Hex):");
                if (secretHex != null && !secretHex.trim().isEmpty()) {
                    try {
                        File encryptedFile = fileChooser.getSelectedFile();
                        String outputFileName = dec(encryptedFile, secretHex, "DecryptedOutput", statusArea, progressBar);
                        statusArea.setText("File decrypted successfully.\nDecrypted file saved in 'decFiles' directory as " + outputFileName);
                    } catch (Exception ex) {
                        statusArea.setText("Decryption error: " + ex.getMessage() + "\nEnsure you used the correct shared secret.");
                        progressBar.setValue(0);
                        ex.printStackTrace();
                    }
                } else {
                    statusArea.setText("Decryption cancelled: No shared secret provided.");
                    progressBar.setValue(0);
                }
            }
        });

        frame.setVisible(true);
    }
}