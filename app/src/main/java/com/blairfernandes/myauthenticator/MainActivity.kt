package com.blairfernandes.myauthenticator

import android.Manifest
import android.app.KeyguardManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview as CameraXPreview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.navigation.NavController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.blairfernandes.myauthenticator.ui.theme.MyAuthenticatorTheme
import com.google.zxing.*
import com.google.zxing.common.HybridBinarizer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.util.* 
import java.util.concurrent.Executors
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and

private const val TAG_QR_ANALYZER = "QrCodeAnalyzer"
private const val TAG_OTP_PARSER = "OtpAuthParser"
private const val TAG_QR_SCAN_SCREEN = "QrScanScreen"
private const val ACCOUNTS_FILE_NAME = "accounts_data.json"
private const val TAG_STORAGE = "AccountStorage"

// Account Storage Functions
fun saveAccountsToFile(context: Context, accounts: List<Account>) {
    try {
        val jsonArray = JSONArray()
        for (account in accounts) {
            val jsonObject = JSONObject()
            jsonObject.put("id", account.id)
            jsonObject.put("serviceName", account.serviceName)
            jsonObject.put("username", account.username)
            jsonObject.put("secret", account.secret)
            jsonArray.put(jsonObject)
        }
        val file = File(context.filesDir, ACCOUNTS_FILE_NAME)
        file.writeText(jsonArray.toString())
        Log.d(TAG_STORAGE, "Accounts saved successfully to $ACCOUNTS_FILE_NAME")
    } catch (e: IOException) {
        Log.e(TAG_STORAGE, "Error saving accounts to file: ${e.message}", e)
    } catch (e: Exception) {
        Log.e(TAG_STORAGE, "General error saving accounts: ${e.message}", e)
    }
}

fun loadAccountsFromFile(context: Context): List<Account> {
    val file = File(context.filesDir, ACCOUNTS_FILE_NAME)
    if (!file.exists()) {
        Log.d(TAG_STORAGE, "$ACCOUNTS_FILE_NAME does not exist. Returning empty list.")
        return emptyList()
    }
    return try {
        val jsonString = file.readText()
        val jsonArray = JSONArray(jsonString)
        val accounts = mutableListOf<Account>()
        for (i in 0 until jsonArray.length()) {
            val jsonObject = jsonArray.getJSONObject(i)
            accounts.add(
                Account(
                    id = jsonObject.getString("id"),
                    serviceName = jsonObject.getString("serviceName"),
                    username = jsonObject.getString("username"),
                    secret = jsonObject.getString("secret")
                )
            )
        }
        Log.d(TAG_STORAGE, "Accounts loaded successfully from $ACCOUNTS_FILE_NAME. Count: ${accounts.size}")
        accounts
    } catch (e: IOException) {
        Log.e(TAG_STORAGE, "Error reading accounts from file: ${e.message}", e)
        emptyList()
    } catch (e: org.json.JSONException) {
        Log.e(TAG_STORAGE, "Error parsing JSON from file: ${e.message}", e)
        emptyList() // Or handle corrupted file, e.g., by deleting it
    } catch (e: Exception) {
        Log.e(TAG_STORAGE, "General error loading accounts: ${e.message}", e)
        emptyList()
    }
}


// Base32 Decoding Utility Object
object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private val DECODABET = IntArray(256) {
        ALPHABET.indexOf(it.toChar().uppercaseChar()) // -1 for invalid chars
    }

    fun decode(s: String): ByteArray {
        val stripped = s.uppercase(Locale.ROOT).replace("=", "")
        if (stripped.isEmpty()) throw IllegalArgumentException("Input string is empty after stripping.")

        val out = ByteArray(stripped.length * 5 / 8)
        var buffer = 0
        var bitsLeft = 0
        var outputIndex = 0

        for (char in stripped) {
            val value = DECODABET[char.code]
            if (value < 0) throw IllegalArgumentException("Invalid character in Base32 string: $char")

            buffer = (buffer shl 5) or value
            bitsLeft += 5

            if (bitsLeft >= 8) {
                out[outputIndex++] = (buffer shr (bitsLeft - 8)).toByte()
                bitsLeft -= 8
            }
        }
        return out.copyOfRange(0, outputIndex)
    }

    fun isValid(s: String): Boolean {
        if (s.isBlank()) return false
        val stripped = s.uppercase(Locale.ROOT).replace("=", "")
        if (stripped.isEmpty()) return false
        for (char in stripped) {
            if (ALPHABET.indexOf(char.uppercaseChar()) < 0) {
                return false
            }
        }
        return true
    }
     fun canBeDecoded(s: String): Boolean {
        if (s.isBlank()) return false
        return try {
            decode(s)
            true
        } catch (e: IllegalArgumentException) {
            false
        }
    }
}

// TOTP Generation (RFC 6238)
fun generateTotp(secret: String, timeEpochSeconds: Long, timeStep: Int = 30, digits: Int = 6): String {
    return try {
        val key = Base32.decode(secret)
        if (key.isEmpty()) return "Error"
        val counter = timeEpochSeconds / timeStep
        val counterBytes = ByteBuffer.allocate(8).putLong(counter).array()
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "RAW_TOKEN_DATA"))
        val hmacResult = mac.doFinal(counterBytes)
        val offset = (hmacResult[hmacResult.size - 1] and 0x0F).toInt()
        val binaryCode = ((hmacResult[offset].toInt() and 0x7F) shl 24)
            .or((hmacResult[offset + 1].toInt() and 0xFF) shl 16)
            .or((hmacResult[offset + 2].toInt() and 0xFF) shl 8)
            .or((hmacResult[offset + 3].toInt() and 0xFF))
        val otp = binaryCode % Math.pow(10.0, digits.toDouble()).toInt()
        String.format(Locale.US, "%0${digits}d", otp)
    } catch (e: Exception) {
        Log.e("TOTP_GENERATION", "Error generating TOTP for secret '$secret': ${e.message}", e)
        "Error"
    }
}

data class Account(val serviceName: String, val username: String, val secret: String, val id: String = UUID.randomUUID().toString())

sealed class Screen(val route: String) {
    object Dashboard : Screen("dashboard")
    object AddAccount : Screen("add_account")
    object ManualAccountEntry : Screen("manual_account_entry")
    object QrScan : Screen("qr_scan")
    object EditAccount : Screen("edit_account/{accountId}") {
        fun createRoute(accountId: String) = "edit_account/$accountId"
    }
}

data class OtpAuthUri(val label: String, val secret: String, val issuer: String?) // Issuer can be null

fun parseOtpAuthUri(uriString: String): OtpAuthUri? {
    Log.d(TAG_OTP_PARSER, "Attempting to parse URI: $uriString")
    return try {
        val uri = uriString.toUri()
        if (uri.scheme != "otpauth" || uri.authority != "totp") {
            Log.e(TAG_OTP_PARSER, "URI scheme or authority incorrect. Scheme: ${uri.scheme}, Authority: ${uri.authority}")
            return null
        }
        val path = uri.path
        if (path == null) {
            Log.e(TAG_OTP_PARSER, "URI path is null.")
            return null
        }
        val label = Uri.decode(path.trimStart('/')).trim() // This is usually accountname or issuer:accountname
        val secret = uri.getQueryParameter("secret")
        if (secret == null) {
            Log.e(TAG_OTP_PARSER, "Secret parameter is null in URI.")
            return null
        }
        Log.d(TAG_OTP_PARSER, "Secret from URI: $secret")
        if (!Base32.isValid(secret)) {
            Log.e(TAG_OTP_PARSER, "Invalid Base32 secret in OTP URI: $secret. isValid: ${Base32.isValid(secret)}")
            return null
        }
        val issuer = uri.getQueryParameter("issuer") // This can be null
        Log.d(TAG_OTP_PARSER, "Successfully parsed OTP URI. Label: $label, Issuer: $issuer, Secret: $secret")
        OtpAuthUri(label, secret, issuer)
    } catch (e: Exception) {
        Log.e(TAG_OTP_PARSER, "Error parsing OTP URI: $uriString", e)
        null
    }
}

@OptIn(ExperimentalMaterial3Api::class)
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val deviceIsSecure = keyguardManager.isDeviceSecure

        val loadedAccounts = loadAccountsFromFile(this)

        setContent {
            MyAuthenticatorTheme {
                val navController = rememberNavController()
                val accountsList = remember { mutableStateListOf<Account>().apply { addAll(loadedAccounts) } }
                val context = LocalContext.current // For saving files

                NavHost(navController = navController, startDestination = Screen.Dashboard.route) {
                    composable(Screen.Dashboard.route) {
                        DashboardScaffold(
                            navController = navController,
                            accounts = accountsList,
                            isDeviceSecure = deviceIsSecure,
                            onDeleteAccount = { account -> 
                                accountsList.remove(account)
                                saveAccountsToFile(context, accountsList.toList())
                             },
                            onEditAccount = { account -> navController.navigate(Screen.EditAccount.createRoute(account.id)) }
                        )
                    }
                    composable(Screen.AddAccount.route) {
                        AddAccountScreen(navController = navController)
                    }
                    composable(Screen.ManualAccountEntry.route) {
                        ManualEntryScreen(
                            navController = navController,
                            onSaveAccount = { newAccount ->
                                if (!accountsList.any { it.secret == newAccount.secret && it.username == newAccount.username && it.serviceName == newAccount.serviceName }) {
                                    accountsList.add(newAccount)
                                    saveAccountsToFile(context, accountsList.toList())
                                }
                                navController.popBackStack(Screen.Dashboard.route, inclusive = false)
                            }
                        )
                    }
                    composable(Screen.QrScan.route) {
                        QrScanScreen(
                            navController = navController,
                            onAccountScanned = { newAccount ->
                                Log.i(TAG_QR_SCAN_SCREEN, "Account successfully scanned and processed callback in NavHost: Service='${newAccount.serviceName}', User='${newAccount.username}'")
                                if (!accountsList.any { it.secret == newAccount.secret && it.username == newAccount.username && it.serviceName == newAccount.serviceName }) {
                                    accountsList.add(newAccount)
                                    saveAccountsToFile(context, accountsList.toList())
                                    Log.d(TAG_QR_SCAN_SCREEN, "New account added and saved.")
                                } else {
                                     Log.d(TAG_QR_SCAN_SCREEN, "Account already exists, not adding or saving.")
                                }
                                if (navController.currentDestination?.route == Screen.QrScan.route) {
                                     navController.popBackStack(Screen.Dashboard.route, inclusive = false)
                                } else {
                                     Log.w(TAG_QR_SCAN_SCREEN, "NavHost: current destination is not QrScan (${navController.currentDestination?.route}), not popping stack.")
                                }
                            }
                        )
                    }
                    composable(
                        route = Screen.EditAccount.route,
                        arguments = listOf(navArgument("accountId") { type = NavType.StringType })
                    ) {
                        val accountId = it.arguments?.getString("accountId")
                        val accountToEdit = accountsList.find { acc -> acc.id == accountId }
                        if (accountToEdit != null) {
                            EditAccountScreen(navController = navController, account = accountToEdit, onSaveAccount = { updatedAccount ->
                                val index = accountsList.indexOfFirst { acc -> acc.id == updatedAccount.id }
                                if (index != -1) {
                                    accountsList[index] = updatedAccount
                                    saveAccountsToFile(context, accountsList.toList())
                                }
                                navController.popBackStack(Screen.Dashboard.route, inclusive = false)
                            })
                        } else {
                            Text("Account not found. Please go back.", modifier = Modifier.padding(16.dp))
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScaffold(
    navController: NavController,
    accounts: List<Account>,
    isDeviceSecure: Boolean,
    onDeleteAccount: (Account) -> Unit,
    onEditAccount: (Account) -> Unit
) {
    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = { TopAppBar(title = { Text("My Authenticator") }) },
        floatingActionButton = {
            FloatingActionButton(onClick = { navController.navigate(Screen.AddAccount.route) }) {
                Icon(Icons.Filled.Add, contentDescription = "Add new account")
            }
        }
    ) { innerPadding ->
        Column(modifier = Modifier.padding(innerPadding).fillMaxSize()) {
            if (!isDeviceSecure) {
                Text(
                    text = "Warning: Your device does not have a screen lock. Please set one up in system settings for app security.",
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.errorContainer).padding(12.dp),
                    textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyMedium
                )
            }
            MainDashboardScreen(accounts = accounts, onDeleteAccount = onDeleteAccount, onEditAccount = onEditAccount, modifier = Modifier.weight(1f))
        }
    }
}

@Composable
fun AccountCard(
    account: Account,
    onDelete: (Account) -> Unit,
    onEdit: (Account) -> Unit,
    modifier: Modifier = Modifier
) {
    var currentTotp by remember { mutableStateOf("------") }
    var remainingTime by remember { mutableIntStateOf(30) }
    var menuExpanded by remember { mutableStateOf(false) }
    var showDeleteDialog by remember { mutableStateOf(false) }
    val context = LocalContext.current

    LaunchedEffect(key1 = account.secret, key2 = Unit) {
        while (true) {
            val epochSeconds = System.currentTimeMillis() / 1000
            val timeStep = 30
            remainingTime = (timeStep - (epochSeconds % timeStep)).toInt()
            currentTotp = generateTotp(account.secret, epochSeconds, timeStep = timeStep)
            val delayMillis = if (remainingTime <=1 && epochSeconds % timeStep != 0L) {
                 ( (timeStep - (epochSeconds % timeStep)) * 1000L) + 200L
            } else {
                1000L
            }
            delay(delayMillis)
        }
    }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text("Confirm Delete") },
            text = { Text("Are you sure you want to delete the account for '${account.serviceName} (${account.username})'? This action cannot be undone.") },
            confirmButton = {
                Button(
                    onClick = {
                        onDelete(account) // This will trigger saveAccountsToFile in NavHost
                        showDeleteDialog = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                Button(onClick = { showDeleteDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp, horizontal = 8.dp)
            .clickable {
                if (currentTotp != "Error" && currentTotp != "------") {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = ClipData.newPlainText("TOTP Code", currentTotp.replace(" ", ""))
                    clipboard.setPrimaryClip(clip)
                    Toast.makeText(context, "Code copied to clipboard", Toast.LENGTH_SHORT).show()
                } else {
                     Toast.makeText(context, "Cannot copy invalid code", Toast.LENGTH_SHORT).show()
                }
            },
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = account.serviceName, style = MaterialTheme.typography.titleMedium)
                Text(text = account.username, style = MaterialTheme.typography.bodySmall) // Changed from @username to just username
                Spacer(modifier = Modifier.height(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val displayTotp = if (currentTotp != "Error" && currentTotp.length == 6 && currentTotp != "------") {
                        currentTotp.substring(0, 3) + " " + currentTotp.substring(3)
                    } else {
                        currentTotp
                    }
                    Text(text = displayTotp, style = MaterialTheme.typography.headlineMedium.copy(fontFamily = FontFamily.Monospace))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(text = "⏱️ ${remainingTime}s", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                }
            }
            Box {
                IconButton(onClick = { menuExpanded = true }) {
                    Icon(Icons.Filled.MoreVert, contentDescription = "More options")
                }
                DropdownMenu(
                    expanded = menuExpanded,
                    onDismissRequest = { menuExpanded = false }
                ) {
                    DropdownMenuItem(
                        text = { Text("Edit") },
                        onClick = { onEdit(account); menuExpanded = false },
                        leadingIcon = { Icon(Icons.Filled.Edit, contentDescription = "Edit Account") }
                    )
                    DropdownMenuItem(
                        text = { Text("Delete") },
                        onClick = { showDeleteDialog = true; menuExpanded = false },
                        leadingIcon = { Icon(Icons.Filled.Delete, contentDescription = "Delete Account") }
                    )
                }
            }
        }
    }
}

@Composable
fun MainDashboardScreen(
    accounts: List<Account>,
    onDeleteAccount: (Account) -> Unit,
    onEditAccount: (Account) -> Unit,
    modifier: Modifier = Modifier
) {
    LazyColumn(modifier = modifier.padding(vertical = 8.dp)) {
        items(accounts, key = { account -> account.id }) { account ->
            AccountCard(account = account, onDelete = onDeleteAccount, onEdit = onEditAccount)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddAccountScreen(navController: NavController) {
    Scaffold(
        topBar = {
            TopAppBar(title = { Text("Add Account") }, navigationIcon = {
                IconButton(onClick = { navController.navigateUp() }) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                }
            })
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier.padding(innerPadding).fillMaxSize().padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Button(onClick = { navController.navigate(Screen.QrScan.route) }, modifier = Modifier.fillMaxWidth()) { Text("Scan QR Code") }
            Button(onClick = { navController.navigate(Screen.ManualAccountEntry.route) }, modifier = Modifier.fillMaxWidth()) { Text("Enter Manually") }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ManualEntryScreen(navController: NavController, onSaveAccount: (Account) -> Unit) {
    var serviceName by remember { mutableStateOf("") }
    var userName by remember { mutableStateOf("") }
    var secretKey by remember { mutableStateOf("") }
    var isSecretKeyValid by remember(secretKey) { mutableStateOf(Base32.isValid(secretKey) || secretKey.isEmpty()) }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("Add Account Manually") }, navigationIcon = {
                IconButton(onClick = { navController.navigateUp() }) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                }
            })
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier.padding(innerPadding).fillMaxSize().padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            OutlinedTextField(value = serviceName, onValueChange = { serviceName = it }, label = { Text("Service Name (e.g., Google)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
            OutlinedTextField(value = userName, onValueChange = { userName = it }, label = { Text("Username (e.g., user@example.com)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
            OutlinedTextField(
                value = secretKey,
                onValueChange = { 
                    secretKey = it
                    isSecretKeyValid = Base32.isValid(it) || it.isEmpty()
                },
                label = { Text("Secret Key (Base32)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                isError = !isSecretKeyValid && secretKey.isNotEmpty(),
                supportingText = { if (!isSecretKeyValid && secretKey.isNotEmpty()) Text("Invalid Base32 characters") else null}
            )
            Spacer(modifier = Modifier.weight(1f))
            Button(
                onClick = { 
                    if(Base32.canBeDecoded(secretKey)) {
                        onSaveAccount(Account(serviceName, userName, secretKey)) // onSaveAccount will trigger saveAccountsToFile
                    } else {
                        isSecretKeyValid = false
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = serviceName.isNotBlank() && userName.isNotBlank() && secretKey.isNotBlank() && Base32.canBeDecoded(secretKey)
            ) { Text("Save Account") }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrScanScreen(navController: NavController, onAccountScanned: (Account) -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val cameraProviderFuture = remember { ProcessCameraProvider.getInstance(context) }
    var hasCameraPermission by remember { mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) }
    var qrCodeProcessed by remember { mutableStateOf(false) }

    val cameraExecutor = remember { Executors.newSingleThreadExecutor() }
    val scope = rememberCoroutineScope()

    DisposableEffect(lifecycleOwner) {
        onDispose {
            Log.d(TAG_QR_SCAN_SCREEN, "QrScanScreen disposing. Shutting down camera executor.")
            cameraExecutor.shutdown()
        }
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
        onResult = { granted -> hasCameraPermission = granted }
    )

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("Scan QR Code") }, navigationIcon = {
                IconButton(onClick = {
                    if (navController.currentDestination?.route == Screen.QrScan.route) {
                        navController.navigateUp()
                    }
                }) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                }
            })
        }
    ) { innerPadding ->
        Box(modifier = Modifier.padding(innerPadding).fillMaxSize()) {
            if (hasCameraPermission) {
                AndroidView(
                    factory = { viewContext ->
                        val previewView = PreviewView(viewContext)
                        val cameraProvider = cameraProviderFuture.get()
                        val cameraPreview = CameraXPreview.Builder().build().also {
                            it.setSurfaceProvider(previewView.surfaceProvider)
                        }
                        val imageAnalysis = ImageAnalysis.Builder()
                            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                            .build()
                            .also { analysisUseCase ->
                                analysisUseCase.setAnalyzer(cameraExecutor, QrCodeAnalyzer { resultText ->
                                    scope.launch(Dispatchers.Main) {
                                        Log.d(TAG_QR_SCAN_SCREEN, "Analyzer received result: $resultText")
                                        if (!qrCodeProcessed && lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                            parseOtpAuthUri(resultText)?.let { otpData ->
                                                // Determine service and user more robustly
                                                val labelParts = otpData.label.split(':', limit = 2)
                                                val derivedIssuer = otpData.issuer?.takeIf { it.isNotBlank() }
                                                val serviceNameFromLabel = if (labelParts.size > 1 && derivedIssuer == null) labelParts[0].trim() else null
                                                val userNameFromLabel = if (labelParts.size > 1) labelParts[1].trim() else labelParts[0].trim()

                                                val finalServiceName = derivedIssuer ?: serviceNameFromLabel ?: "Unknown Service"
                                                val finalUserName = userNameFromLabel

                                                val account = Account(serviceName = finalServiceName, username = finalUserName, secret = otpData.secret)
                                                
                                                if (navController.currentDestination?.route == Screen.QrScan.route) {
                                                    Log.i(TAG_QR_SCAN_SCREEN, "Account created. Service='$finalServiceName', User='$finalUserName'. Calling onAccountScanned.")
                                                    qrCodeProcessed = true
                                                    onAccountScanned(account) // This will trigger saveAccountsToFile in NavHost
                                                } else {
                                                    Log.w(TAG_QR_SCAN_SCREEN, "QR Scanned, but current destination is not QrScanScreen (${navController.currentDestination?.route}). Skipping callback.")
                                                }
                                            } ?: run {
                                                Log.w(TAG_QR_SCAN_SCREEN, "parseOtpAuthUri returned null for: $resultText.")
                                                Toast.makeText(context, "Invalid OTP QR Code", Toast.LENGTH_LONG).show()
                                            }
                                        } else {
                                            val reason = if(qrCodeProcessed) "already processed" else "lifecycle not active (${lifecycleOwner.lifecycle.currentState})"
                                            Log.d(TAG_QR_SCAN_SCREEN, "Skipping result ($reason): $resultText")
                                        }
                                    }
                                })
                            }
                        try {
                            cameraProvider.unbindAll()
                            cameraProvider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, cameraPreview, imageAnalysis)
                            Log.d(TAG_QR_SCAN_SCREEN, "Camera bound to lifecycle.")
                        } catch (e: Exception) {
                            Log.e(TAG_QR_SCAN_SCREEN, "CameraX binding failed", e)
                        }
                        previewView
                    },
                    modifier = Modifier.fillMaxSize()
                )
            } else {
                Column(
                    modifier = Modifier.fillMaxSize().padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text("Camera permission is required to scan QR codes.")
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(onClick = { permissionLauncher.launch(Manifest.permission.CAMERA) }) {
                        Text("Grant Permission")
                    }
                }
            }
        }
    }
}

private class QrCodeAnalyzer(private val onQrCodeScanned: (String) -> Unit) : ImageAnalysis.Analyzer {
    private val reader = MultiFormatReader().apply {
        val hints = mutableMapOf<DecodeHintType, Any>()
        hints[DecodeHintType.POSSIBLE_FORMATS] = listOf(BarcodeFormat.QR_CODE)
        setHints(hints)
    }

    @androidx.annotation.OptIn(androidx.camera.core.ExperimentalGetImage::class)
    override fun analyze(imageProxy: ImageProxy) {
        try {
            val mediaImage = imageProxy.image ?: return
            val imageWidth = mediaImage.width
            val imageHeight = mediaImage.height
            val planes = mediaImage.planes
            if (planes.isEmpty()) return

            val yPlane = planes[0]
            val yBuffer = yPlane.buffer
            val yData = ByteArray(yBuffer.remaining())
            yBuffer.get(yData)

            val source = PlanarYUVLuminanceSource(yData, imageWidth, imageHeight, 0, 0, imageWidth, imageHeight, false)
            val binaryBitmap = BinaryBitmap(HybridBinarizer(source))

            try {
                val result = reader.decodeWithState(binaryBitmap)
                Log.d(TAG_QR_ANALYZER, "QR Code decoded: ${result.text}")
                onQrCodeScanned(result.text)
            } catch (e: NotFoundException) {
                // No QR code found, expected case, can be noisy if logged every frame
            } catch (e: Exception) {
                Log.e(TAG_QR_ANALYZER, "Error decoding QR code content: ${e.message}", e)
            } finally {
                reader.reset()
            }
        } catch (e: Exception) {
            Log.e(TAG_QR_ANALYZER, "Error in analyze method: ${e.message}", e)
        } finally {
            imageProxy.close()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditAccountScreen(navController: NavController, account: Account, onSaveAccount: (Account) -> Unit) {
    var serviceName by remember(account.id) { mutableStateOf(account.serviceName) }
    var userName by remember(account.id) { mutableStateOf(account.username) }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("Edit Account") }, navigationIcon = {
                IconButton(onClick = { navController.navigateUp() }) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                }
            })
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier.padding(innerPadding).fillMaxSize().padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            OutlinedTextField(
                value = serviceName,
                onValueChange = { serviceName = it },
                label = { Text("Service Name") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            OutlinedTextField(
                value = userName,
                onValueChange = { userName = it },
                label = { Text("Username") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.weight(1f))
            Button(
                onClick = { 
                    val updatedAccount = account.copy(serviceName = serviceName, username = userName)
                    onSaveAccount(updatedAccount) // This will trigger saveAccountsToFile in NavHost
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = serviceName.isNotBlank() && userName.isNotBlank()
            ) { Text("Save Changes") }
        }
    }
}

// --- Previews ---
@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true)
@Composable
fun DashboardScaffoldPreview() {
    val sampleAccountsPreview = remember { mutableStateListOf(Account("Google", "preview@gmail.com", "JBSWY3DPEHPK3PXP")) }
    MyAuthenticatorTheme { DashboardScaffold(navController = rememberNavController(), accounts = sampleAccountsPreview, isDeviceSecure = true, onDeleteAccount = {}, onEditAccount = {}) }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true)
@Composable
fun AccountCardPreview() {
    MyAuthenticatorTheme {
        AccountCard(Account("Example Service", "user@example.com", "JBSWY3DPEHPK3PXP"), onDelete = {}, onEdit = {})
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true)
@Composable
fun EditAccountScreenPreview() {
    MyAuthenticatorTheme {
        EditAccountScreen(navController = rememberNavController(), account = Account("Test", "test@example.com", "JBSWY3DPEHPK3PXP"), onSaveAccount = {})
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true)
@Composable
fun AddAccountScreenPreview() {
    MyAuthenticatorTheme { AddAccountScreen(navController = rememberNavController()) }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true)
@Composable
fun ManualEntryScreenPreview() {
    MyAuthenticatorTheme { ManualEntryScreen(navController = rememberNavController(), onSaveAccount = {}) }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true)
@Composable
fun QrScanScreenPreview() {
    MyAuthenticatorTheme {
        Box(modifier = Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
            Text("Camera preview or permission request for QR Scan screen would be shown here.")
        }
    }
}
