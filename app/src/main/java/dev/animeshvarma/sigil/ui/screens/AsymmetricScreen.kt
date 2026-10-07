package dev.animeshvarma.sigil.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.animeshvarma.sigil.SigilViewModel
import dev.animeshvarma.sigil.crypto.AsymmetricEngine
import dev.animeshvarma.sigil.ui.components.SigilSegmentedControl
import dev.animeshvarma.sigil.ui.components.StyledLayerContainer

/** 密钥库里属于非对称密钥对的私钥，别名统一带这个前缀。 */
private const val KEY_PREFIX = "私钥·"

@Composable
fun AsymmetricScreen(viewModel: SigilViewModel) {
    val entries by viewModel.vaultEntries.collectAsState()
    val keyAliases = remember(entries) { entries.map { it.alias }.filter { it.startsWith(KEY_PREFIX) } }

    var tab by remember { mutableIntStateOf(0) }
    var selectedAlias by remember { mutableStateOf<String?>(null) }
    var selectedPublicKey by remember { mutableStateOf("") }

    // 没选或选中的被删了：默认选第一个
    LaunchedEffect(keyAliases) {
        if (selectedAlias == null || selectedAlias !in keyAliases) selectedAlias = keyAliases.firstOrNull()
    }
    // 由私钥推出公钥用于展示
    LaunchedEffect(selectedAlias, keyAliases) {
        val alias = selectedAlias
        if (alias == null) {
            selectedPublicKey = ""
        } else {
            viewModel.viewKey(alias) { sk ->
                selectedPublicKey = sk?.let { runCatching { AsymmetricEngine.publicKeyFromPrivate(it) }.getOrNull() } ?: ""
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        SigilSegmentedControl(
            items = listOf("密钥对", "加密", "解密"),
            selectedIndex = tab,
            onItemSelection = { tab = it },
            modifier = Modifier.fillMaxWidth(0.9f)
        )
        Spacer(Modifier.height(12.dp))

        when (tab) {
            0 -> KeyPairTab(
                viewModel = viewModel,
                keyAliases = keyAliases,
                selectedAlias = selectedAlias,
                selectedPublicKey = selectedPublicKey,
                onSelect = { selectedAlias = it }
            )
            1 -> EncryptTab(myPublicKey = selectedPublicKey)
            else -> DecryptTab(
                viewModel = viewModel,
                keyAliases = keyAliases,
                selectedAlias = selectedAlias,
                onSelect = { selectedAlias = it }
            )
        }
    }
}

@Composable
private fun KeyPairTab(
    viewModel: SigilViewModel,
    keyAliases: List<String>,
    selectedAlias: String?,
    selectedPublicKey: String,
    onSelect: (String) -> Unit
) {
    val clipboard = LocalClipboardManager.current
    var newName by remember { mutableStateOf("") }
    var aliasToDelete by remember { mutableStateOf<String?>(null) }

    val fullAlias = KEY_PREFIX + newName.trim()
    val nameTaken = newName.isNotBlank() && keyAliases.any { it.equals(fullAlias, ignoreCase = true) }

    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Text(
            "公钥可以随便发给别人，别人用它加密后只有你能解开；私钥只保存在你的密钥库里，不要泄露。",
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(12.dp))

        OutlinedTextField(
            value = newName,
            onValueChange = { newName = it },
            label = { Text("新密钥对名称") },
            singleLine = true,
            isError = nameTaken,
            supportingText = { if (nameTaken) Text("该名称已存在") },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp)
        )
        Spacer(Modifier.height(8.dp))
        Button(
            enabled = newName.isNotBlank() && !nameTaken,
            onClick = {
                val pair = AsymmetricEngine.generateKeyPair()
                viewModel.saveToVault(fullAlias, pair.privateKey)
                newName = ""
            },
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(24.dp)
        ) { Text("生成密钥对（X25519）") }

        Spacer(Modifier.height(16.dp))

        if (keyAliases.isEmpty()) {
            Text("还没有密钥对，先生成一个吧。", color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            Text("我的密钥对", fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(6.dp))
            keyAliases.forEach { alias ->
                StyledLayerContainer(modifier = Modifier.padding(bottom = 8.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(selected = alias == selectedAlias, onClick = { onSelect(alias) })
                        Text(alias.removePrefix(KEY_PREFIX), modifier = Modifier.weight(1f), fontSize = 16.sp)
                        IconButton(onClick = { aliasToDelete = alias }) {
                            Icon(Icons.Default.Delete, "删除", tint = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }

            if (selectedPublicKey.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = selectedPublicKey,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("公钥（可分享给对方）") },
                    textStyle = LocalTextStyleMono(),
                    modifier = Modifier.fillMaxWidth().height(130.dp),
                    shape = RoundedCornerShape(20.dp),
                    trailingIcon = {
                        IconButton(onClick = { clipboard.setText(AnnotatedString(selectedPublicKey)) }) {
                            Icon(Icons.Default.ContentCopy, "复制公钥")
                        }
                    }
                )
            }
        }
        Spacer(Modifier.height(24.dp))
    }

    if (aliasToDelete != null) {
        AlertDialog(
            onDismissRequest = { aliasToDelete = null },
            title = { Text("删除密钥对？") },
            text = { Text("删除后，用对应公钥加密过的内容将永远无法解密。此操作不可恢复。") },
            confirmButton = {
                Button(
                    onClick = { viewModel.deleteFromVault(aliasToDelete!!); aliasToDelete = null },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                ) { Text("删除") }
            },
            dismissButton = { TextButton(onClick = { aliasToDelete = null }) { Text("取消") } }
        )
    }
}

@Composable
private fun EncryptTab(myPublicKey: String) {
    val clipboard = LocalClipboardManager.current
    var recipientKey by remember { mutableStateOf("") }
    var plaintext by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        OutlinedTextField(
            value = recipientKey,
            onValueChange = { recipientKey = it },
            label = { Text("对方的公钥（SGPK1:…）") },
            textStyle = LocalTextStyleMono(),
            modifier = Modifier.fillMaxWidth().height(110.dp),
            shape = RoundedCornerShape(20.dp)
        )
        if (myPublicKey.isNotEmpty()) {
            TextButton(onClick = { recipientKey = myPublicKey }) { Text("填入我自己的公钥（加密给自己）") }
        }
        Spacer(Modifier.height(6.dp))
        OutlinedTextField(
            value = plaintext,
            onValueChange = { plaintext = it },
            label = { Text("要加密的内容") },
            modifier = Modifier.fillMaxWidth().height(130.dp),
            shape = RoundedCornerShape(20.dp)
        )
        Spacer(Modifier.height(12.dp))
        Button(
            onClick = {
                error = null
                try {
                    result = AsymmetricEngine.encrypt(recipientKey, plaintext)
                } catch (e: Exception) {
                    result = ""
                    error = e.message ?: "加密失败。"
                }
            },
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(24.dp)
        ) { Text("加密") }

        error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error, fontSize = 13.sp)
        }

        if (result.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = result,
                onValueChange = {},
                readOnly = true,
                label = { Text("密文（发给对方即可）") },
                textStyle = LocalTextStyleMono(),
                modifier = Modifier.fillMaxWidth().height(160.dp),
                shape = RoundedCornerShape(20.dp),
                trailingIcon = {
                    IconButton(onClick = { clipboard.setText(AnnotatedString(result)) }) {
                        Icon(Icons.Default.ContentCopy, "复制密文")
                    }
                }
            )
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "说明：这是匿名加密，对方只能确认内容没被改动，无法确认是谁发的。",
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun DecryptTab(
    viewModel: SigilViewModel,
    keyAliases: List<String>,
    selectedAlias: String?,
    onSelect: (String) -> Unit
) {
    var ciphertext by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        if (keyAliases.isEmpty()) {
            Text("还没有密钥对，请先到「密钥对」页生成。", color = MaterialTheme.colorScheme.onSurfaceVariant)
            return@Column
        }

        Text("用哪个私钥解密", fontWeight = FontWeight.SemiBold)
        keyAliases.forEach { alias ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = alias == selectedAlias, onClick = { onSelect(alias) })
                Text(alias.removePrefix(KEY_PREFIX))
            }
        }
        Spacer(Modifier.height(8.dp))

        OutlinedTextField(
            value = ciphertext,
            onValueChange = { ciphertext = it },
            label = { Text("密文（SGAE1:…）") },
            textStyle = LocalTextStyleMono(),
            modifier = Modifier.fillMaxWidth().height(150.dp),
            shape = RoundedCornerShape(20.dp)
        )
        Spacer(Modifier.height(12.dp))
        Button(
            enabled = selectedAlias != null,
            onClick = {
                error = null
                viewModel.viewKey(selectedAlias!!) { sk ->
                    if (sk == null) {
                        result = ""
                        error = "读取私钥失败。"
                    } else {
                        try {
                            result = AsymmetricEngine.decrypt(sk, ciphertext)
                        } catch (e: Exception) {
                            result = ""
                            error = e.message ?: "解密失败。"
                        }
                    }
                }
            },
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(24.dp)
        ) { Text("解密") }

        error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error, fontSize = 13.sp)
        }

        if (result.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = result,
                onValueChange = {},
                readOnly = true,
                label = { Text("解密结果") },
                modifier = Modifier.fillMaxWidth().height(140.dp),
                shape = RoundedCornerShape(20.dp),
                trailingIcon = {
                    IconButton(onClick = { viewModel.copyToClipboardSecurely(result, "印记解密结果") }) {
                        Icon(Icons.Default.ContentCopy, "安全复制")
                    }
                }
            )
        }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun LocalTextStyleMono() =
    LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp)
