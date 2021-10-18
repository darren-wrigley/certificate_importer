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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * certificate util. extract all certs from a website & store to file + import
 * into truststore
 */
public final class App {
    private static String folder = "./certs";
    private String truststoreFile = "";
    private String truststorePass = "";
    // initialize args for cert ripper module, starting with "print -f pem"
    private List<String> ripperArgs = new ArrayList<String>() {
        {
            add("print");
            add("-f");
            add("pem");
        }
    };

    private App(String[] args) {
        // boolean hasPass = false;
        for (String arg : args) {
            if (arg.startsWith("--url")) {
                ripperArgs.add(arg);
            } else if (arg.startsWith("--keystore=")) {
                this.truststoreFile = arg.substring("--keystore=".length());
            } else if (arg.startsWith("--storepass=")) {
                this.truststorePass = arg.substring("--storepass=".length());
                // hasPass = true;
                // this.truststorePass = arg.substring("--storepass=".length());
            } else {
                System.out.println("unknown parameter: " + arg);
            }
        }

        // if (!hasPass) {
        // System.out.println("no password passed for truststore: prompt for input");
        // }
    }

    /**
     * Says hello to the world.
     *
     * @param args The arguments of the program.
     */
    public static void main(String[] args) {
        System.out.println("web app certificate export & trustore import");
        if (args.length < 2) {
            System.out.println("missing required arguments:");
            System.out.print("\t--url=https://<server_with_optional_port> ");
            System.out.print("--keystore <truststore_file_to_import certs> ");
            System.out.println("--storepass=<truststore password>");
            System.out.println("\tNotes:\tyou can pass multiple --url arguments");
            System.out.println("\t\tif you do use --storepass, you will be prompted for a password");
            System.exit(1);
        }

        // create the folder that holds the cert files, if not already exists
        File directory = new File(folder);
        if (!directory.exists()) {
            System.out.println("\tfolder: " + folder + " does not exist, creating it");
            directory.mkdir();
        }

        App certImporter = new App(args);
        certImporter.run();

    }

    private void run() {
        System.out.println("running cert export & import for truststore");
        ByteArrayOutputStream baos = get_certificates();
        List<String> certAliases = this.save_certificates(baos);
        this.update_truststore(certAliases);
    }

    private ByteArrayOutputStream get_certificates() {
        // use cert ripper to extract certificate chains from each url
        System.out.println("extracting certicates...");
        // String[] parms = { "print", "--url=https://www.google.com", "-f", "pem" };
        String[] parms = this.ripperArgs.toArray(new String[ripperArgs.size()]);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        PrintStream old = System.out;
        System.setOut(ps);
        nl.altindag.ssl.App.main(parms);
        System.out.flush();
        System.setOut(old);

        return baos;
    }

    private List<String> save_certificates(ByteArrayOutputStream baos) {
        Map<String, String> aliasMap = extractCertificates(baos);
        List<String> subjects = new ArrayList<String>();
        // save the certificate entries to .pem files
        for (Map.Entry<String, String> entry : aliasMap.entrySet()) {
            String certFile = folder + "/" + entry.getKey() + ".pem";
            int certLines = entry.getValue().split("\n").length;
            subjects.add(entry.getKey());
            System.out.println("\twriting certificate: " + certFile + " with " + certLines + " lines");

            try {
                FileWriter writer = new FileWriter(certFile);
                writer.write(entry.getValue());
                writer.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }

        System.out.println(subjects.size() + " certificates extracted");
        Collections.reverse(subjects);
        return subjects;
    }

    private Map<String, String> extractCertificates(ByteArrayOutputStream baos) {
        Map<String, String> certMap = new LinkedHashMap<String, String>();
        String[] lines = baos.toString().split(System.getProperty("line.separator"));
        String subject = "";
        boolean inCert = false;
        List<String> certVals = new ArrayList<String>();
        for (String tmpLine : lines) {
            if (tmpLine.startsWith("Certificates for url = ")) {
                System.out.println("website... " + tmpLine);
            } else if (tmpLine.startsWith("subject=CN=")) {
                subject = extractSubject(tmpLine);
            } else if ("-----BEGIN CERTIFICATE-----".equals(tmpLine)) {
                inCert = true;
                certVals.clear();
                certVals.add(tmpLine);
            } else if ("-----END CERTIFICATE-----".equals(tmpLine)) {
                inCert = false;
                certVals.add(tmpLine);
                certMap.put(subject, String.join("\n", certVals));
            } else if (inCert) {
                certVals.add(tmpLine);
            }
        }
        return certMap;
    }

    private String extractSubject(String subjectLine) {
        int end = subjectLine.length();
        if (subjectLine.indexOf(",") > 0) {
            end = subjectLine.indexOf(",");
        }
        return subjectLine.substring("subject=CN=".length(), end);
    }

    private int update_truststore(List<String> subjects) {
        // System.out.println("importing certificates in reversed order: " + subjects);
        int updateCount = 0;
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            // load the cert
            ks = KeyStore.getInstance("JKS");
            System.out.println("loading keystore: " + truststoreFile);
            ks.load(new FileInputStream(truststoreFile), truststorePass.toCharArray());

            for (String certAlias : subjects) {
                if (ks.containsAlias(certAlias)) {
                    System.out.println("\talias: " + certAlias + " already in keystore");
                    continue;
                }
                updateCount++;
                System.out.println("\tadding new alias '" + certAlias + "' to keystore");
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                FileInputStream is = new FileInputStream("./certs/" + certAlias + ".pem");
                X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
                is.close();
                ks.setCertificateEntry(certAlias, cer);
            }
            if (updateCount > 0) {
                System.out.println("updating keystore, with " + updateCount + " new entries");
                FileOutputStream out = new FileOutputStream(truststoreFile);
                ks.store(out, truststorePass.toCharArray());
                out.close();
            } else {
                System.out.println("no new aliases to add, keystore was not updated");
            }
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return updateCount;
    }
}
