# ProGuard rules for MTProtoCrypto SDK consumers
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Keep public domain models, repositories, and use cases
-keep class com.gargpadmakar.mtproto.crypto.domain.model.** { *; }
-keep class com.gargpadmakar.mtproto.crypto.domain.repository.** { *; }
-keep class com.gargpadmakar.mtproto.crypto.domain.usecase.** { *; }
-keep class com.gargpadmakar.mtproto.crypto.security.** { *; }

# Keep public API crypto engine methods
-keep class com.gargpadmakar.mtproto.crypto.data.crypto.ApiCryptoEngine {
    public <methods>;
}
