package dev.animeshvarma.sigil.data

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.core.content.edit
import dev.animeshvarma.sigil.crypto.CryptoEngine
import dev.animeshvarma.sigil.util.SecureMemory
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class VaultEntry(
    val alias: String,
    val timestamp: Long,
    val strengthScore: Int, // Cached score for UI (0-100)
    val strengthLabel: String
)

class KeystoreRepository(context: Context) {

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }
    private val prefs: SharedPreferences = context.getSharedPreferences("sigil_vault_v3", Context.MODE_PRIVATE)

    init {
        ensureVaultInitialized()
    }


    private fun ensureVaultInitialized() {
        if (!prefs.contains(VAULT_KEY_PREF)) {
            // 1. Generate Hardware Wrapper Key
            if (!keyStore.containsAlias(HARDWARE_ALIAS)) {
                val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                val spec = KeyGenParameterSpec.Builder(
                    HARDWARE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
                generator.init(spec)
                generator.generateKey()
            }

            // 2. Generate Random Vault Seed
            val vaultSeed = ByteArray(32) // 256 bits
            SecureRandom().nextBytes(vaultSeed)

            // 3. Encrypt Seed with Hardware Key
            val hwKey = keyStore.getKey(HARDWARE_ALIAS, null) as SecretKey
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, hwKey)

            val iv = cipher.iv
            val encryptedSeed = cipher.doFinal(vaultSeed)

            // 4. Pack (IV + EncryptedData) & Save
            val blob = ByteArray(1 + iv.size + encryptedSeed.size)
            blob[0] = iv.size.toByte()

            iv.copyInto(blob, destinationOffset = 1)
            encryptedSeed.copyInto(blob, destinationOffset = 1 + iv.size)

            prefs.edit {
                putString(VAULT_KEY_PREF, Base64.encodeToString(blob, Base64.NO_WRAP))
            }

            // 5. Wipe memory
            Arrays.fill(vaultSeed, 0.toByte())
        }
    }

    private fun getVaultKey(): CharArray {
        val base64Blob = prefs.getString(VAULT_KEY_PREF, null)
            ?: throw IllegalStateException("密钥库已损坏：缺少主种子。")

        val blob = Base64.decode(base64Blob, Base64.NO_WRAP)

        // Unpack IV
        val ivSize = blob[0].toInt()
        val iv = ByteArray(ivSize)
        val encryptedSeed = ByteArray(blob.size - 1 - ivSize)

        blob.copyInto(iv, destinationOffset = 0, startIndex = 1, endIndex = 1 + ivSize)
        blob.copyInto(encryptedSeed, destinationOffset = 0, startIndex = 1 + ivSize, endIndex = blob.size)

        // Decrypt using Hardware Key
        val hwKey = keyStore.getKey(HARDWARE_ALIAS, null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, hwKey, GCMParameterSpec(128, iv))

        val seedBytes = cipher.doFinal(encryptedSeed)

        // Convert to Hex CharArray
        val hexChars = toHex(seedBytes)

        // Wipe intermediate bytes
        Arrays.fill(seedBytes, 0.toByte())

        return hexChars
    }

    fun saveToVault(alias: String, secret: CharArray, score: Int, label: String) {
        if (prefs.contains("DATA_$alias")) {
            deleteEntry(alias)
        }

        val vaultKey = getVaultKey()

        try {
            val secretBytes = toBytes(secret)

            val encryptedBlob = CryptoEngine.encrypt(
                data = secretBytes,
                password = vaultKey,
                algorithms = STORAGE_ALGORITHMS,
                kdfConfig = VAULT_KDF_CONFIG,
                compress = false,
                logCallback = {}
            )

            Arrays.fill(secretBytes, 0.toByte())

            prefs.edit {
                putString("DATA_$alias", encryptedBlob)
                putLong("TIME_$alias", System.currentTimeMillis())
                putInt("SCORE_$alias", score)
                putString("LABEL_$alias", label)
            }

        } finally {
            SecureMemory.wipe(vaultKey)
        }
    }

    fun loadFromVault(alias: String): String? {
        val encryptedBlob = prefs.getString("DATA_$alias", null) ?: return null
        val vaultKey = getVaultKey()

        return try {
            val decryptedBytes = CryptoEngine.decrypt(
                encryptedData = encryptedBlob,
                password = vaultKey,
                kdfConfig = VAULT_KDF_CONFIG,
                logCallback = {}
            )
            val result = String(decryptedBytes, StandardCharsets.UTF_8)
            Arrays.fill(decryptedBytes, 0.toByte())
            result
        } catch (e: Exception) {
            e.printStackTrace()
            null
        } finally {
            SecureMemory.wipe(vaultKey)
        }
    }

    fun renameEntry(oldAlias: String, newAlias: String): Boolean {
        if (oldAlias == newAlias) return true
        // 目标名称已存在时拒绝重命名，避免静默覆盖已有密钥
        if (prefs.contains("DATA_$newAlias")) return false

        val secretString = loadFromVault(oldAlias) ?: return false
        val secretChars = secretString.toCharArray()
        val score = prefs.getInt("SCORE_$oldAlias", 0)
        val label = prefs.getString("LABEL_$oldAlias", "未知") ?: "未知"

        saveToVault(newAlias, secretChars, score, label)

        SecureMemory.wipe(secretChars)
        deleteEntry(oldAlias)

        return true
    }

    fun getEntries(): List<VaultEntry> {
        return prefs.all.keys
            .filter { it.startsWith("DATA_") }
            .map { key ->
                val alias = key.removePrefix("DATA_")
                if (alias.startsWith(INTERNAL_PREFIX)) return@map null
                VaultEntry(
                    alias = alias,
                    timestamp = prefs.getLong("TIME_$alias", 0L),
                    strengthScore = prefs.getInt("SCORE_$alias", 0),
                    strengthLabel = localizeLabel(prefs.getString("LABEL_$alias", "") ?: "")
                )
            }
            .filterNotNull()
            .sortedByDescending { it.timestamp }
    }

    fun deleteEntry(alias: String) {
        prefs.edit {
            remove("DATA_$alias")
            remove("TIME_$alias")
            remove("SCORE_$alias")
            remove("LABEL_$alias")
        }
    }

    // --- Helpers ---
    // 历史数据里的强度标签是英文，这里仅在显示时转换，不改动已存储的数据
    private fun localizeLabel(label: String): String = when (label) {
        "Empty" -> "空"
        "Weak" -> "弱"
        "Fair" -> "一般"
        "Strong" -> "强"
        "Unbreakable" -> "极强"
        "Unknown" -> "未知"
        else -> label
    }

    private fun toHex(bytes: ByteArray): CharArray {
        val hexChars = CharArray(bytes.size * 2)
        for (j in bytes.indices) {
            val v = bytes[j].toInt() and 0xFF
            hexChars[j * 2] = hexArray[v ushr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
        }
        return hexChars
    }

    private fun toBytes(chars: CharArray): ByteArray {
        val charBuffer = java.nio.CharBuffer.wrap(chars)
        val byteBuffer = StandardCharsets.UTF_8.encode(charBuffer)

        val bytes = byteBuffer.array().copyOfRange(byteBuffer.position(), byteBuffer.limit())
        byteBuffer.array().fill(0.toByte())

        return bytes
    }

    companion object {
        private const val INTERNAL_PREFIX = "_SIGIL_"
        private const val HARDWARE_ALIAS = "SIGIL_HARDWARE_WRAPPER"
        private const val VAULT_KEY_PREF = "ENCRYPTED_VAULT_SEED"

        private val hexArray = "0123456789ABCDEF".toCharArray()

        private val STORAGE_ALGORITHMS = listOf(
            CryptoEngine.Algorithm.AES_GCM,
            CryptoEngine.Algorithm.CHACHA20_POLY1305,
            CryptoEngine.Algorithm.TWOFISH_CBC,
            CryptoEngine.Algorithm.SERPENT_CBC
        )

        private val VAULT_KDF_CONFIG = CryptoEngine.KdfConfig(
            iterations = 10,
            memoryPow2 = 16,
            parallelism = 4
        )
    }
}
