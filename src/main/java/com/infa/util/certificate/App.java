package com.infa.util.certificate;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

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
        String[] lines = baos.toString().split(System.getProperty("line.separator"));
        for (String tmpLine : lines) {
            if (tmpLine.startsWith("subject=CN=")) {
                System.out.println("Subject line=" + tmpLine);
                int end = tmpLine.length();
                if (tmpLine.indexOf(",") > 0) {
                    end = tmpLine.indexOf(",");
                }
                subject = tmpLine.substring("subject=CN=".length(), end);
                System.out.println("\t" + subject);
            }
        }

    }
}
