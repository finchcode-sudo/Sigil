package dev.animeshvarma.sigil.util

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import dev.animeshvarma.sigil.crypto.CryptoEngine
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.zip.CRC32

/**
 * Steganography helpers: hides data inside the low-order bits of ordinary carriers
 * (invisible zero-width Unicode characters for text, LSB of pixel channels for images)
 * so its presence isn't visually obvious. Optionally layers CryptoEngine encryption on
 * top of the hidden payload for confidentiality.
 */
object StegoEngine {

    // Fast, fixed KDF used only for optional stego payload encryption (not user-configurable,
    // since stego capacity is tiny and this is a convenience layer, not the primary vault).
    private val stegoKdf = CryptoEngine.KdfConfig(iterations = 2, memoryPow2 = 14, parallelism = 1)

    // 旧版编码（v1）：仅用于兼容解码。U+200B 在复制/传输中容易被清理，新版不再使用。
    private const val ZW_ZERO = '\u200B' // zero-width space -> bit 0
    private const val ZW_ONE = '\u200C'  // zero-width non-joiner -> bit 1
    private const val ZW_START = '\u200D' // zero-width joiner -> marks payload start

    // 新版编码（v2）：0/1 分别用 U+200C / U+200D，起始符用 U+2060（词连接符），
    // 并在载荷前后加入 2 字节长度和 2 字节校验，数据缺失或损坏时能明确报错。
    private const val ZW2_ZERO = '\u200C'
    private const val ZW2_ONE = '\u200D'
    private const val ZW2_START = '\u2060'

    // --- TEXT STEGANOGRAPHY ---

    /**
     * Hides [secret] inside invisible zero-width characters appended to [cover].
     * If [password] is non-blank, the secret is AES-GCM encrypted first.
     */
    fun encodeText(cover: String, secret: String, password: String): String {
        require(secret.isNotEmpty()) { "隐藏内容不能为空。" }

        val payloadBytes: ByteArray = if (password.isNotBlank()) {
            val pwd = password.toCharArray()
            try {
                CryptoEngine.encryptRaw(
                    data = secret.toByteArray(Charsets.UTF_8),
                    password = pwd,
                    algorithm = CryptoEngine.Algorithm.AES_GCM,
                    kdfConfig = stegoKdf
                ).toByteArray(Charsets.UTF_8)
            } finally {
                pwd.fill('\u0000')
            }
        } else {
            secret.toByteArray(Charsets.UTF_8)
        }
        require(payloadBytes.size <= 0xFFFF) { "隐藏内容过长（最多约 64KB）。" }

        val crc = checksum16(payloadBytes)
        val frame = ByteArrayOutputStream().apply {
            write((payloadBytes.size shr 8) and 0xFF)
            write(payloadBytes.size and 0xFF)
            write(payloadBytes)
            write((crc shr 8) and 0xFF)
            write(crc and 0xFF)
        }.toByteArray()

        val sb = StringBuilder(cover)
        sb.append(ZW2_START)
        for (bit in bytesToBits(frame)) sb.append(if (bit) ZW2_ONE else ZW2_ZERO)
        return sb.toString()
    }

    /**
     * Extracts a hidden payload from [stego] text, decrypting it with [password] if provided.
     * Returns null if no hidden payload marker is found.
     * 新版（v2）优先；找不到 v2 起始符时回退到旧版（v1）格式。
     */
    fun decodeText(stego: String, password: String): String? {
        val v2 = stego.indexOf(ZW2_START)
        return if (v2 != -1) decodeTextV2(stego, v2, password) else decodeTextLegacy(stego, password)
    }

    private fun decodeTextV2(stego: String, startIndex: Int, password: String): String? {
        val bits = mutableListOf<Boolean>()
        for (i in startIndex + 1 until stego.length) {
            when (stego[i]) {
                ZW2_ZERO -> bits.add(false)
                ZW2_ONE -> bits.add(true)
                else -> {}
            }
        }
        if (bits.isEmpty()) return null

        val diag = "（检测到：起始符 ${stego.count { it == ZW2_START }} 个，" +
            "0 位 ${stego.count { it == ZW2_ZERO }} 个，1 位 ${stego.count { it == ZW2_ONE }} 个，" +
            "共 ${bits.size} 位）"
        require(bits.size >= 32 && bits.size % 8 == 0) {
            "隐藏数据不完整：位数不对，部分零宽字符可能在复制或传输中丢失。$diag"
        }

        val frame = bitsToBytes(bits)
        val len = ((frame[0].toInt() and 0xFF) shl 8) or (frame[1].toInt() and 0xFF)
        require(frame.size == len + 4) {
            "隐藏数据不完整：长度与头部记录不符（应为 ${len + 4} 字节，实际 ${frame.size} 字节）。$diag"
        }
        val payload = frame.copyOfRange(2, 2 + len)
        val crc = ((frame[2 + len].toInt() and 0xFF) shl 8) or (frame[3 + len].toInt() and 0xFF)
        require(crc == checksum16(payload)) { "隐藏数据校验失败，内容已被改动或损坏。$diag" }

        return payloadToText(payload, password, diag)
    }

    private fun decodeTextLegacy(stego: String, password: String): String? {
        val startIndex = stego.indexOf(ZW_START)
        if (startIndex == -1) return null

        val bits = mutableListOf<Boolean>()
        for (i in startIndex + 1 until stego.length) {
            when (stego[i]) {
                ZW_ZERO -> bits.add(false)
                ZW_ONE -> bits.add(true)
                else -> {} // ignore any stray characters
            }
        }
        if (bits.isEmpty()) return null

        val diag = "（旧格式；检测到：起始符 ${stego.count { it == ZW_START }} 个，" +
            "0 位 ${stego.count { it == ZW_ZERO }} 个，1 位 ${stego.count { it == ZW_ONE }} 个，" +
            "共 ${bits.size} 位）"
        require(bits.size % 8 == 0) {
            "隐藏数据不完整：位数不是 8 的倍数，部分零宽字符（尤其是 U+200B）可能在复制或传输中丢失。$diag"
        }
        return payloadToText(bitsToBytes(bits), password, diag)
    }

    private fun payloadToText(payloadBytes: ByteArray, password: String, diag: String): String {
        return if (password.isNotBlank()) {
            val pwd = password.toCharArray()
            try {
                val decrypted = CryptoEngine.decryptRaw(
                    encryptedData = String(payloadBytes, Charsets.UTF_8),
                    password = pwd,
                    algorithm = CryptoEngine.Algorithm.AES_GCM,
                    kdfConfig = stegoKdf
                )
                String(decrypted, Charsets.UTF_8)
            } finally {
                pwd.fill('\u0000')
            }
        } else {
            try {
                Charsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(payloadBytes)).toString()
            } catch (_: java.nio.charset.CharacterCodingException) {
                throw IllegalArgumentException(
                    "隐藏数据已损坏，无法还原为文字：可能丢失了零宽字符，或这段内容设置了密码。$diag"
                )
            }
        }
    }

    private fun checksum16(data: ByteArray): Int {
        val c = CRC32()
        c.update(data)
        return (c.value and 0xFFFF).toInt()
    }

    // --- IMAGE STEGANOGRAPHY (LSB) ---

    /**
     * Hides [secret] in the least-significant bit of each RGB channel of the image at [sourceUri].
     * Returns a new Bitmap (must be saved as PNG/lossless to preserve the hidden data).
     */
    fun encodeImage(context: Context, sourceUri: Uri, secret: String, password: String): Bitmap {
        val original = loadBitmap(context, sourceUri)
        val bitmap = original.copy(Bitmap.Config.ARGB_8888, true)

        val payloadBytes: ByteArray = if (password.isNotBlank()) {
            val pwd = password.toCharArray()
            try {
                CryptoEngine.encryptRaw(
                    data = secret.toByteArray(Charsets.UTF_8),
                    password = pwd,
                    algorithm = CryptoEngine.Algorithm.AES_GCM,
                    kdfConfig = stegoKdf
                ).toByteArray(Charsets.UTF_8)
            } finally {
                pwd.fill('\u0000')
            }
        } else {
            secret.toByteArray(Charsets.UTF_8)
        }

        val lengthPrefixed = ByteArrayOutputStream().apply {
            write((payloadBytes.size shr 24) and 0xFF)
            write((payloadBytes.size shr 16) and 0xFF)
            write((payloadBytes.size shr 8) and 0xFF)
            write(payloadBytes.size and 0xFF)
            write(payloadBytes)
        }.toByteArray()

        val bits = bytesToBits(lengthPrefixed)
        val capacityBits = bitmap.width * bitmap.height * 3
        require(bits.size <= capacityBits) {
            "图片容量不足：可容纳 ${capacityBits / 8} 字节，需要 ${bits.size / 8} 字节。请使用更大的图片。"
        }

        var bitIndex = 0
        outer@ for (y in 0 until bitmap.height) {
            for (x in 0 until bitmap.width) {
                if (bitIndex >= bits.size) break@outer
                val pixel = bitmap.getPixel(x, y)
                var r = (pixel shr 16) and 0xFF
                var g = (pixel shr 8) and 0xFF
                var b = pixel and 0xFF
                val a = (pixel shr 24) and 0xFF

                if (bitIndex < bits.size) { r = setLsb(r, bits[bitIndex]); bitIndex++ }
                if (bitIndex < bits.size) { g = setLsb(g, bits[bitIndex]); bitIndex++ }
                if (bitIndex < bits.size) { b = setLsb(b, bits[bitIndex]); bitIndex++ }

                bitmap.setPixel(x, y, (a shl 24) or (r shl 16) or (g shl 8) or b)
            }
        }
        return bitmap
    }

    /**
     * Extracts a hidden payload previously embedded by [encodeImage] from the image at [sourceUri].
     */
    fun decodeImage(context: Context, sourceUri: Uri, password: String): String {
        val bitmap = loadBitmap(context, sourceUri)

        // Read 32-bit length header first (first 32 bits => ceil(32/3) = 11 pixels)
        val headerBits = mutableListOf<Boolean>()
        var bitIndex = 0
        headerLoop@ for (y in 0 until bitmap.height) {
            for (x in 0 until bitmap.width) {
                val pixel = bitmap.getPixel(x, y)
                val r = (pixel shr 16) and 0xFF
                val g = (pixel shr 8) and 0xFF
                val b = pixel and 0xFF
                val channels = intArrayOf(r, g, b)
                for (c in channels) {
                    if (bitIndex < 32) {
                        headerBits.add((c and 1) == 1)
                        bitIndex++
                    }
                }
                if (bitIndex >= 32) break@headerLoop
            }
        }
        require(headerBits.size == 32) { "图片过小，无法读取隐写头部。" }
        val lengthBytes = bitsToBytes(headerBits)
        val payloadLength = ((lengthBytes[0].toInt() and 0xFF) shl 24) or
            ((lengthBytes[1].toInt() and 0xFF) shl 16) or
            ((lengthBytes[2].toInt() and 0xFF) shl 8) or
            (lengthBytes[3].toInt() and 0xFF)

        require(payloadLength in 1..(bitmap.width * bitmap.height * 3 / 8)) { "未检测到有效的隐写数据，或密码/图片不匹配。" }

        val totalBits = 32 + payloadLength * 8
        val allBits = mutableListOf<Boolean>()
        var idx = 0
        allLoop@ for (y in 0 until bitmap.height) {
            for (x in 0 until bitmap.width) {
                val pixel = bitmap.getPixel(x, y)
                val r = (pixel shr 16) and 0xFF
                val g = (pixel shr 8) and 0xFF
                val b = pixel and 0xFF
                for (c in intArrayOf(r, g, b)) {
                    if (idx < totalBits) {
                        allBits.add((c and 1) == 1)
                        idx++
                    }
                }
                if (idx >= totalBits) break@allLoop
            }
        }

        val payloadBits = allBits.subList(32, allBits.size)
        val payloadBytes = bitsToBytes(payloadBits)

        return if (password.isNotBlank()) {
            val pwd = password.toCharArray()
            try {
                val decrypted = CryptoEngine.decryptRaw(
                    encryptedData = String(payloadBytes, Charsets.UTF_8),
                    password = pwd,
                    algorithm = CryptoEngine.Algorithm.AES_GCM,
                    kdfConfig = stegoKdf
                )
                String(decrypted, Charsets.UTF_8)
            } finally {
                pwd.fill('\u0000')
            }
        } else {
            String(payloadBytes, Charsets.UTF_8)
        }
    }

    private fun loadBitmap(context: Context, uri: Uri): Bitmap {
        val stream = context.contentResolver.openInputStream(uri)
            ?: throw IllegalArgumentException("无法读取图片。")
        return stream.use { BitmapFactory.decodeStream(it) ?: throw IllegalArgumentException("无法解码图片。") }
    }

    private fun setLsb(value: Int, bit: Boolean): Int {
        return if (bit) (value or 1) else (value and 0xFE)
    }

    private fun bytesToBits(bytes: ByteArray): List<Boolean> {
        val bits = ArrayList<Boolean>(bytes.size * 8)
        for (byte in bytes) {
            for (i in 7 downTo 0) {
                bits.add(((byte.toInt() shr i) and 1) == 1)
            }
        }
        return bits
    }

    private fun bitsToBytes(bits: List<Boolean>): ByteArray {
        val usable = bits.size - (bits.size % 8)
        val out = ByteArray(usable / 8)
        for (i in 0 until usable step 8) {
            var byte = 0
            for (j in 0 until 8) {
                byte = (byte shl 1) or (if (bits[i + j]) 1 else 0)
            }
            out[i / 8] = byte.toByte()
        }
        return out
    }
}
