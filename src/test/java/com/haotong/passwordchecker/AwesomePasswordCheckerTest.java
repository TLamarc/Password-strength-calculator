package com.haotong.passwordchecker;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AwesomePasswordCheckerTest {

    @Test
    void md5ShouldMatchKnownValue() {
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        String hash = AwesomePasswordChecker.computeMd5("abc");
        assertEquals("900150983cd24fb0d6963f7d28e17f72", hash);
    }
}
