package com.haotong.passwordchecker;

public final class Main {

    private Main() {
        // Utility class: prevent instantiation.
    }

    /**
     * Program entry point.
     *
     * @param args command-line arguments
     * @throws Exception if an error occurs
     */
    public static void main(final String[] args) throws Exception {
        AwesomePasswordChecker checker = AwesomePasswordChecker.getInstance();

        String[] passwords = {
                "password",
                "Password123",
                "P@ssw0rd!",
                "aaaaaaaa",
                "ThisIsAVeryLongPassword123!!!",
                "LamarHHTT9527!"
        };

        for (String pwd : passwords) {
            double distance = checker.getDistance(pwd);
            System.out.println(pwd + " -> distance = " + distance);
        }
    }
}

