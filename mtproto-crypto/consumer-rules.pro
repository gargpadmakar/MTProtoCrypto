# ProGuard rules for MTProtoCrypto SDK consumers
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Keep public domain models and repository interfaces
-keep class com.gargpadmakar.mtproto.crypto.domain.model.** { *; }
-keep class com.gargpadmakar.mtproto.crypto.domain.repository.** { *; }
-keep class com.gargpadmakar.mtproto.crypto.domain.usecase.** { *; }
-keep class com.gargpadmakar.mtproto.crypto.security.** { *; }

