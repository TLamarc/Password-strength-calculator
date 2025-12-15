package com.haotong.passwordchecker;

import java.util.List; //

public class Main {
    public static void main(String[] args) throws Exception {
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


/*
package com.haotong.passwordchecker;


public class Main {
    public static void main(String[] args) throws Exception {
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
} */
