@file:Suppress("AssignedValueIsNeverRead")

package dev.animeshvarma.sigil.ui.screens

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import java.security.SecureRandom
import dev.animeshvarma.sigil.SigilViewModel
import dev.animeshvarma.sigil.data.VaultEntry
import dev.animeshvarma.sigil.ui.components.StyledLayerContainer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun KeystoreScreen(viewModel: SigilViewModel) {
    val entries by viewModel.vaultEntries.collectAsState()

    KeystoreContent(
        entries = entries,
        onAdd = { alias, secret -> viewModel.saveToVault(alias, secret) },
        onDelete = { viewModel.deleteFromVault(it) },
        onRename = { old, new -> viewModel.renameVaultEntry(old, new) },
        onView = { alias, callback -> viewModel.viewKey(alias, callback) },
        onCopy = { key -> viewModel.copyToClipboardSecurely(key, "印记密钥") }
    )
}

@Composable
fun KeystoreContent(
    entries: List<VaultEntry>,
    onAdd: (String, String) -> Unit,
    onDelete: (String) -> Unit,
    onRename: (String, String) -> Unit,
    onView: (String, (String?) -> Unit) -> Unit,
    onCopy: (String) -> Unit
) {
    var entryToDelete by remember { mutableStateOf<VaultEntry?>(null) }
    var entryToRename by remember { mutableStateOf<VaultEntry?>(null) }
    var entryToWarn by remember { mutableStateOf<VaultEntry?>(null) }
    var entryToView by remember { mutableStateOf<VaultEntry?>(null) }

    var renameText by remember { mutableStateOf("") }
    var revealedKey by remember { mutableStateOf("") }

    var showAddDialog by remember { mutableStateOf(false) }
    var addName by remember { mutableStateOf("") }
    var addSecret by remember { mutableStateOf("") }
    var addSecretVisible by remember { mutableStateOf(false) }

    fun aliasTaken(name: String, except: String? = null): Boolean =
        entries.any { it.alias.equals(name.trim(), ignoreCase = true) && it.alias != except }

    Box(modifier = Modifier.fillMaxSize()) {
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
            modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
            shape = RoundedCornerShape(16.dp)
        ) {
            Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Security, null, modifier = Modifier.size(32.dp))
                Spacer(modifier = Modifier.width(16.dp))
                Column {
                    Text("硬件密钥库", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                    Text("密钥由 Android 可信执行环境（TEE）加密。", fontSize = 12.sp, color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f))
                }
            }
        }

        if (entries.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Default.KeyOff, null, tint = MaterialTheme.colorScheme.outline, modifier = Modifier.size(48.dp))
                    Spacer(Modifier.height(8.dp))
                    Text("密钥库为空。", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "点击右下角「＋」添加，或在加密页保存当前密钥。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.outline
                    )
                }
            }
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(bottom = 80.dp)
            ) {
                items(entries) { entry ->
                    VaultItem(
                        entry = entry,
                        onDelete = { entryToDelete = entry },
                        onRename = {
                            renameText = entry.alias
                            entryToRename = entry
                        },
                        onView = { entryToWarn = entry }
                    )
                }
            }
        }
    }

    FloatingActionButton(
        onClick = {
            addName = ""
            addSecret = ""
            addSecretVisible = false
            showAddDialog = true
        },
        modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp)
    ) { Icon(Icons.Default.Add, "添加密钥") }
    }

    if (showAddDialog) {
        val nameTaken = addName.isNotBlank() && aliasTaken(addName)
        AlertDialog(
            onDismissRequest = { showAddDialog = false; addSecret = "" },
            icon = { Icon(Icons.Default.Key, null, tint = MaterialTheme.colorScheme.primary) },
            title = { Text("添加密钥") },
            text = {
                Column {
                    OutlinedTextField(
                        value = addName,
                        onValueChange = { addName = it },
                        label = { Text("名称") },
                        singleLine = true,
                        isError = nameTaken,
                        supportingText = { if (nameTaken) Text("该名称已存在") },
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = addSecret,
                        onValueChange = { addSecret = it },
                        label = { Text("密钥内容") },
                        singleLine = true,
                        visualTransformation = if (addSecretVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        trailingIcon = {
                            IconButton(onClick = { addSecretVisible = !addSecretVisible }) {
                                Icon(
                                    if (addSecretVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                    if (addSecretVisible) "隐藏" else "显示"
                                )
                            }
                        },
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    )
                    TextButton(onClick = {
                        addSecret = generateRandomKey()
                        addSecretVisible = true
                    }) {
                        Icon(Icons.Default.Refresh, null, Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("随机生成（32 位）")
                    }
                }
            },
            confirmButton = {
                Button(
                    enabled = addName.isNotBlank() && addSecret.isNotEmpty() && !nameTaken,
                    onClick = {
                        onAdd(addName.trim(), addSecret)
                        showAddDialog = false
                        addSecret = ""
                    }
                ) { Text("保存") }
            },
            dismissButton = { TextButton(onClick = { showAddDialog = false; addSecret = "" }) { Text("取消") } }
        )
    }

    if (entryToDelete != null) {
        AlertDialog(
            onDismissRequest = { entryToDelete = null },
            icon = { Icon(Icons.Default.DeleteForever, null, tint = MaterialTheme.colorScheme.error) },
            title = { Text("删除密钥？") },
            text = { Text("此操作不可逆。使用「${entryToDelete?.alias}」加密的所有数据将永久无法访问。") },
            confirmButton = {
                Button(
                    onClick = {
                        entryToDelete?.let { onDelete(it.alias) }
                        entryToDelete = null
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                ) { Text("删除") }
            },
            dismissButton = { TextButton(onClick = { entryToDelete = null }) { Text("取消") } }
        )
    }

    if (entryToRename != null) {
        val renameTaken = renameText.isNotBlank() && aliasTaken(renameText, except = entryToRename?.alias)
        AlertDialog(
            onDismissRequest = { entryToRename = null },
            icon = { Icon(Icons.Default.Edit, null) },
            title = { Text("重命名密钥") },
            text = {
                OutlinedTextField(
                    value = renameText,
                    onValueChange = { renameText = it },
                    label = { Text("新名称") },
                    singleLine = true,
                    isError = renameTaken,
                    supportingText = { if (renameTaken) Text("该名称已存在") },
                    shape = RoundedCornerShape(12.dp)
                )
            },
            confirmButton = {
                Button(enabled = !renameTaken, onClick = {
                    if (renameText.isNotBlank() && entryToRename != null && !renameTaken) {
                        onRename(entryToRename!!.alias, renameText)
                        entryToRename = null
                    }
                }) { Text("保存") }
            },
            dismissButton = { TextButton(onClick = { entryToRename = null }) { Text("取消") } }
        )
    }

    if (entryToWarn != null) {
        AlertDialog(
            onDismissRequest = { entryToWarn = null },
            icon = { Icon(Icons.Default.Visibility, null, tint = MaterialTheme.colorScheme.primary) },
            title = { Text("显示密钥内容？") },
            text = { Text("原始密码/密钥将显示在屏幕上。请确保无人窥屏。") },
            confirmButton = {
                Button(onClick = {
                    val entry = entryToWarn!!
                    entryToWarn = null
                    onView(entry.alias) { key ->
                        revealedKey = key ?: "解密失败"
                        entryToView = entry
                    }
                }) { Text("显示") }
            },
            dismissButton = { TextButton(onClick = { entryToWarn = null }) { Text("取消") } }
        )
    }

    if (entryToView != null) {
        AlertDialog(
            onDismissRequest = { entryToView = null; revealedKey = "" },
            title = { Text(entryToView?.alias ?: "密钥") },
            text = {
                Column {
                    Text(
                        text = revealedKey,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier
                            .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp))
                            .padding(16.dp)
                            .fillMaxWidth()
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "点击「安全复制」安全使用。",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            },
            confirmButton = {
                Button(onClick = {
                    onCopy(revealedKey)
                }) {
                    Icon(Icons.Default.ContentCopy, null, Modifier.size(16.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("安全复制")
                }
            },
            dismissButton = { TextButton(onClick = { entryToView = null; revealedKey = "" }) { Text("关闭") } }
        )
    }
}

@Composable
fun VaultItem(
    entry: VaultEntry,
    onDelete: () -> Unit,
    onRename: () -> Unit,
    onView: () -> Unit
) {
    val dateStr = remember(entry.timestamp) {
        SimpleDateFormat("yyyy年MM月dd日", Locale.CHINA).format(Date(entry.timestamp))
    }

    val strengthColor = when {
        entry.strengthScore >= 95 -> Color(0xFF00E676)
        entry.strengthScore >= 75 -> Color(0xFF81C784)
        entry.strengthScore >= 40 -> Color(0xFFFFD54F)
        else -> Color(0xFFCF6679)
    }

    val strengthFraction = (entry.strengthScore / 100f).coerceIn(0.1f, 1f)

    StyledLayerContainer {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp)
                .animateContentSize(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(entry.alias, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
                Spacer(Modifier.height(6.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier
                            .height(4.dp)
                            .width(60.dp)
                            .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(2.dp))
                    ) {
                        Box(
                            Modifier
                                .fillMaxHeight()
                                .fillMaxWidth(strengthFraction)
                                .background(strengthColor, RoundedCornerShape(2.dp))
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    Text(entry.strengthLabel, fontSize = 11.sp, color = strengthColor, fontWeight = FontWeight.Medium)
                }

                Spacer(Modifier.height(2.dp))
                Text(dateStr, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            IconButton(onClick = onView) { Icon(Icons.Default.Visibility, "查看", tint = MaterialTheme.colorScheme.primary) }
            IconButton(onClick = onRename) { Icon(Icons.Default.Edit, "重命名", tint = MaterialTheme.colorScheme.onSurfaceVariant) }
            IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, "删除", tint = MaterialTheme.colorScheme.error) }
        }
    }
}


private const val KEY_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}"

/** 使用 SecureRandom 生成随机密钥（约 200 位熵）。 */
private fun generateRandomKey(length: Int = 32): String {
    val rnd = SecureRandom()
    return buildString(length) { repeat(length) { append(KEY_ALPHABET[rnd.nextInt(KEY_ALPHABET.length)]) } }
}
