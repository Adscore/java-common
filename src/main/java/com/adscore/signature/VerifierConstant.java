package com.adscore.signature;

import java.util.HashMap;

class VerifierConstant {

     static final HashMap<String, String> results =
            new HashMap<String, String>() {
                {
                    put("0", "ok");
                    put("3", "junk");
                    put("6", "proxy");
                    put("9", "bot");
                }
            };
}
