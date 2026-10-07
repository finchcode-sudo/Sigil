package dev.animeshvarma.sigil.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 非对称（公钥）加密：X25519 密钥协商 + HKDF-SHA256 + AES-256-GCM（ECIES 风格的混合加密）。
 *
 * 加密：每条消息生成一次性临时密钥对，与收件人公钥做 ECDH，导出会话密钥后用 AES-GCM 加密。
 * 只有持有对应私钥的人才能解密。注意：这是"匿名加密"，不证明发送者是谁（没有签名）。
 *
 * 文本格式（均为 Base64URL，无填充）：
 *  - 公钥  "SGPK1:" + 32 字节公钥 + 4 字节校验（用于发现复制不完整/输错）
 *  - 私钥  "SGSK1:" + 32 字节私钥
 *  - 密文  "SGAE1:" + 临时公钥(32) + nonce(12) + AES-GCM 密文及标签
 */
object AsymmetricEngine {

    private const val PK_PREFIX = "SGPK1:"
    private const val SK_PREFIX = "SGSK1:"
    private const val MSG_PREFIX = "SGAE1:"
    private const val KEY_LEN = 32
    private const val NONCE_LEN = 12
    private const val TAG_LEN = 16
    private const val MAX_PLAINTEXT_BYTES = 1_000_000
    private val HKDF_INFO = "sigil-asym-v1".toByteArray(Charsets.UTF_8)

    private val rng = SecureRandom()

    data class KeyPair(val privateKey: String, val publicKey: String)

    fun generateKeyPair(): KeyPair {
        val sk = X25519PrivateKeyParameters(rng)
        val skBytes = sk.encoded
        val pkBytes = sk.generatePublicKey().encoded
        val result = KeyPair(encodePrivate(skBytes), encodePublic(pkBytes))
        skBytes.fill(0)
        return result
    }

    fun publicKeyFromPrivate(privateKey: String): String {
        val skBytes = decodePrivate(privateKey)
        try {
            return encodePublic(X25519PrivateKeyParameters(skBytes, 0).generatePublicKey().encoded)
        } finally {
            skBytes.fill(0)
        }
    }

    /** 用收件人公钥加密文本，返回可直接复制发送的密文字符串。 */
    fun encrypt(recipientPublicKey: String, plaintext: String): String {
        val data = plaintext.toByteArray(Charsets.UTF_8)
        require(data.isNotEmpty()) { "要加密的内容不能为空。" }
        require(data.size <= MAX_PLAINTEXT_BYTES) { "内容过长（最多约 1MB）。" }

        val recipientPk = decodePublic(recipientPublicKey)
        val eph = X25519PrivateKeyParameters(rng)
        val ephPk = eph.generatePublicKey().encoded

        val shared = agree(eph, recipientPk)
        val aesKey = deriveKey(shared, ephPk, recipientPk)
        shared.fill(0)

        val nonce = ByteArray(NONCE_LEN).also { rng.nextBytes(it) }
        val ct = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(TAG_LEN * 8, nonce))
            cipher.updateAAD(ephPk + recipientPk)
            cipher.doFinal(data)
        } finally {
            aesKey.fill(0)
            data.fill(0)
        }
        return MSG_PREFIX + b64(ephPk + nonce + ct)
    }

    /** 用自己的私钥解密密文。密文损坏或私钥不匹配时抛出 IllegalArgumentException。 */
    fun decrypt(privateKey: String, message: String): String {
        val raw = clean(message)
        require(raw.startsWith(MSG_PREFIX)) { "这不是印记非对称密文（应以 $MSG_PREFIX 开头）。" }
        val body = try {
            Base64.getUrlDecoder().decode(raw.removePrefix(MSG_PREFIX))
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("密文格式错误，可能复制不完整。")
        }
        require(body.size >= KEY_LEN + NONCE_LEN + TAG_LEN) { "密文太短，可能复制不完整。" }

        val ephPk = body.copyOfRange(0, KEY_LEN)
        val nonce = body.copyOfRange(KEY_LEN, KEY_LEN + NONCE_LEN)
        val ct = body.copyOfRange(KEY_LEN + NONCE_LEN, body.size)

        val skBytes = decodePrivate(privateKey)
        val sk = X25519PrivateKeyParameters(skBytes, 0)
        skBytes.fill(0)
        val myPk = sk.generatePublicKey().encoded

        val shared = try {
            agree(sk, ephPk)
        } catch (_: Exception) {
            throw IllegalArgumentException("密文无效。")
        }
        val aesKey = deriveKey(shared, ephPk, myPk)
        shared.fill(0)

        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(TAG_LEN * 8, nonce))
            cipher.updateAAD(ephPk + myPk)
            val plain = cipher.doFinal(ct)
            try {
                String(plain, Charsets.UTF_8)
            } finally {
                plain.fill(0)
            }
        } catch (_: Exception) {
            throw IllegalArgumentException("解密失败：私钥不匹配，或密文已被改动。")
        } finally {
            aesKey.fill(0)
        }
    }

    // --- internals ---

    private fun agree(priv: X25519PrivateKeyParameters, peerPk: ByteArray): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(priv)
        val out = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X25519PublicKeyParameters(peerPk, 0), out, 0)
        return out
    }

    private fun deriveKey(shared: ByteArray, ephPk: ByteArray, recipientPk: ByteArray): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(shared, ephPk + recipientPk, HKDF_INFO))
        return ByteArray(32).also { hkdf.generateBytes(it, 0, it.size) }
    }

    private fun checksum(pk: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(pk).copyOf(4)

    private fun encodePublic(pk: ByteArray) = PK_PREFIX + b64(pk + checksum(pk))

    private fun encodePrivate(sk: ByteArray) = SK_PREFIX + b64(sk)

    private fun decodePublic(text: String): ByteArray {
        val raw = clean(text)
        require(raw.startsWith(PK_PREFIX)) { "这不是印记公钥（应以 $PK_PREFIX 开头）。" }
        val bytes = try {
            Base64.getUrlDecoder().decode(raw.removePrefix(PK_PREFIX))
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("公钥格式错误，可能复制不完整。")
        }
        require(bytes.size == KEY_LEN + 4) { "公钥长度不对，可能复制不完整。" }
        val pk = bytes.copyOfRange(0, KEY_LEN)
        require(checksum(pk).contentEquals(bytes.copyOfRange(KEY_LEN, KEY_LEN + 4))) {
            "公钥校验失败，可能复制不完整或输错了字符。"
        }
        return pk
    }

    private fun decodePrivate(text: String): ByteArray {
        val raw = clean(text)
        require(raw.startsWith(SK_PREFIX)) { "这不是印记私钥。" }
        val bytes = try {
            Base64.getUrlDecoder().decode(raw.removePrefix(SK_PREFIX))
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("私钥格式错误。")
        }
        require(bytes.size == KEY_LEN) { "私钥长度不对。" }
        return bytes
    }

    /** 去掉空白和聊天软件可能插入的零宽字符。 */
    private fun clean(s: String): String =
        s.filterNot { it.isWhitespace() || it in "\u200B\u200C\u200D\u2060\uFEFF" }

    private fun b64(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
