package com.infa.util.certificate;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

// import nl.altindag.ssl.*;

/**
 * Hello world!
 */
public final class App {
    private App() {
    }

    /**
     * Says hello to the world.
     *
     * @param args The arguments of the program.
     */
    public static void main(String[] args) {
        System.out.println("Hello World!");
        String[] parms = { "print", "--url=https://www.google.com", "-f", "pem" };

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        PrintStream old = System.out;
        System.setOut(ps);
        System.out.println("Foofoofoo!");
        nl.altindag.ssl.App.main(parms);
        System.out.flush();
        System.setOut(old);

        // System.out.println(baos.toString());
        // System.setOut(new PrintStream(baos));

        String subject = "";
        boolean in_cert = false;
        List<String> cert_vals = new ArrayList<String>();
        List<String> subjects = new ArrayList<String>();
        String[] lines = baos.toString().split(System.getProperty("line.separator"));
        for (String tmpLine : lines) {
            if (tmpLine.startsWith("subject=CN=")) {
                System.out.println("Certificate found: " + tmpLine);
                int end = tmpLine.length();
                if (tmpLine.indexOf(",") > 0) {
                    end = tmpLine.indexOf(",");
                }
                subject = tmpLine.substring("subject=CN=".length(), end);
                subjects.add(subject);
                System.out.println("\t" + subject);
            } else if (tmpLine.equals("-----BEGIN CERTIFICATE-----")) {
                in_cert = true;
                cert_vals.clear();
                cert_vals.add(tmpLine);
            } else if (tmpLine.equals("-----END CERTIFICATE-----")) {
                in_cert = false;
                cert_vals.add(tmpLine);
                // write the cert
                String folder = "./certs";
                String cert_file = folder + "/" + subject + ".pem";
                System.out.println("\tready to write cert: " + cert_file + " with " + cert_vals.size() + " lines");

                File directory = new File(folder);
                if (!directory.exists()) {
                    System.out.println("\tfolder: " + folder + " does not exist, creating it");
                    directory.mkdir();
                }

                try {
                    FileWriter writer = new FileWriter(cert_file);
                    for (String str : cert_vals) {
                        writer.write(str + System.lineSeparator());
                    }
                    writer.close();
                } catch (Exception ex) {
                    ex.printStackTrace();
                }

            } else {
                if (in_cert) {
                    cert_vals.add(tmpLine);
                }
            }
        }

        System.out.println("cert list - read order");
        System.out.println(subjects);
        Collections.reverse(subjects);
        // System.out.println(subjects);
        System.out.println("importing certificates in reversed order: " + subjects);

        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            System.out.println("keystore initialized...");
            char[] pwdArray = "pass2038@infaSSL".toCharArray();
            String keystore = "./certs/clientkeystore";

            // load the cert
            ks = KeyStore.getInstance("JKS");
            try {
                ks.load(new FileInputStream(keystore), pwdArray);
                boolean is_updated = false;

                for (String cert_alias : subjects) {
                    if (ks.containsAlias(cert_alias)) {
                        System.out.println("\t\talias: " + cert_alias + " already in keystore");
                        continue;
                    }
                    is_updated = true;
                    System.out.println("\t\tadding new alias to keystore");
                    CertificateFactory fact = CertificateFactory.getInstance("X.509");
                    FileInputStream is = new FileInputStream("./certs/" + cert_alias + ".pem");
                    X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
                    is.close();

                    ks.setCertificateEntry(cert_alias, cer);
                }
                if (is_updated) {
                    System.out.println("updating keystore...");
                    FileOutputStream out = new FileOutputStream(keystore);
                    ks.store(out, pwdArray);
                    out.close();
                } else {
                    System.out.println("no new aliases to add, keystore was not be updated");
                }
            } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }
}
