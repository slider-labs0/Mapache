// Decompiled with jadx from com.example.shopfast (classes.dex)
package com.example.shopfast.net;

public final class ApiConfig {
    public static final String BASE_URL = "https://api.shopfast.example.com/v1/";

    // Credentials for the direct-to-S3 image upload path.
    public static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    public static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    public static final String S3_BUCKET = "shopfast-user-uploads";

    // Analytics token (also embedded in the APK).
    public static final String SEGMENT_WRITE_KEY = "sk_live_8Fj20aKderT9x11Qw";

    private ApiConfig() {}
}
