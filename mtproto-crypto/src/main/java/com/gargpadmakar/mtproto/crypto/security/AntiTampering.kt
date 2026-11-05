package com.gargpadmakar.mtproto.crypto.security

import android.content.Context
import android.os.Build
import android.os.Debug
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Anti-Reverse Engineering & Device Integrity Detection Suite.
 *
 * Provides defense-in-depth protection against:
 * 1. Rooted Environments (SuperSU, Magisk, KernelSU)
 * 2. Dynamic Instrumentations & Memory Hooking (Frida, Xposed, Substrate)
 * 3. Active Debugging (JDB, IDA Pro, Android Studio LLDB)
 * 4. Android Emulators & Headless Analysis Sandboxes
 */
object AntiTampering {

    private val ROOT_PATHS = arrayOf(
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/sbin/.magisk",
        "/data/adb/magisk"
    )

    private val FRIDA_SIGNATURES = arrayOf(
        "frida-agent",
        "frida-gadget",
        "libfrida",
        "gum-js-loop",
        "gmain"
    )

    /**
     * Checks if device shows indicators of root compromise.
     */
    fun isDeviceRooted(): Boolean {
        // 1. Check build tags
        val buildTags = Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) {
            return true
        }

        // 2. Check root binary paths
        for (path in ROOT_PATHS) {
            try {
                if (File(path).exists()) return true
            } catch (_: SecurityException) {}
        }

        // 3. Check 'which su' execution
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val reader = BufferedReader(process.inputStream.reader())
            val line = reader.readLine()
            reader.close()
            process.destroy()
            !line.isNullOrEmpty()
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Checks if a debugger is actively attached to the application.
     */
    fun isDebuggerAttached(): Boolean {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            return true
        }

        // Check TracerPid in /proc/self/status
        return try {
            val file = File("/proc/self/status")
            if (file.exists()) {
                val reader = BufferedReader(FileReader(file))
                var line: String?
                var tracerPid = 0
                while (reader.readLine().also { line = it } != null) {
                    if (line!!.startsWith("TracerPid:")) {
                        tracerPid = line!!.substring("TracerPid:".length).trim().toIntOrNull() ?: 0
                        break
                    }
                }
                reader.close()
                tracerPid > 0
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Checks if dynamic instrumentation frameworks (Frida) are active or injected.
     */
    fun isFridaDetected(): Boolean {
        // 1. Inspect memory maps for frida shared libraries
        try {
            val mapsFile = File("/proc/self/maps")
            if (mapsFile.exists()) {
                val reader = BufferedReader(FileReader(mapsFile))
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    for (sig in FRIDA_SIGNATURES) {
                        if (line!!.contains(sig, ignoreCase = true)) {
                            reader.close()
                            return true
                        }
                    }
                }
                reader.close()
            }
        } catch (_: Exception) {}

        // 2. Check default Frida server port (27042)
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("127.0.0.1", 27042), 50)
                return true
            }
        } catch (_: Exception) {}

        // 3. Check for frida server binary in /data/local/tmp
        try {
            val tmpDir = File("/data/local/tmp")
            if (tmpDir.exists() && tmpDir.isDirectory) {
                val files = tmpDir.list()
                if (files != null) {
                    for (name in files) {
                        if (name.contains("frida", ignoreCase = true)) {
                            return true
                        }
                    }
                }
            }
        } catch (_: Exception) {}

        return false
    }

    /**
     * Checks if the app is executing inside a generic emulator or simulator.
     */
    fun isEmulator(): Boolean {
        val fingerprint = Build.FINGERPRINT
        val model = Build.MODEL
        val manufacturer = Build.MANUFACTURER
        val brand = Build.BRAND
        val device = Build.DEVICE
        val product = Build.PRODUCT
        val hardware = Build.HARDWARE

        return (fingerprint.startsWith("generic")
                || fingerprint.startsWith("unknown")
                || model.contains("google_sdk")
                || model.contains("Emulator")
                || model.contains("Android SDK built for x86")
                || manufacturer.contains("Genymotion")
                || brand.startsWith("generic") && device.startsWith("generic")
                || "google_sdk" == product
                || hardware.contains("goldfish")
                || hardware.contains("ranchu"))
    }

    /**
     * Convenience method to verify full environment health.
     * Returns true if environment is safe, false if any tampering/instrumentation is detected.
     */
    fun isEnvironmentSafe(): Boolean {
        return !isDeviceRooted() && !isDebuggerAttached() && !isFridaDetected()
    }
}
