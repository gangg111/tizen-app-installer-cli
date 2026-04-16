package com.tizen.installer.ui

import android.app.Application
import android.content.Context
import android.net.Uri
import androidx.activity.result.ActivityResult
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.tizen.installer.installer.TizenInstaller
import com.tizen.installer.network.NetworkService
import com.tizen.installer.network.TvDevice
import com.tizen.installer.signing.SamsungAuth
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val _uiState = MutableStateFlow<AppUiState>(AppUiState.Idle)
    val uiState: StateFlow<AppUiState> = _uiState

    private val _logLines = MutableStateFlow<List<String>>(emptyList())
    val logLines: StateFlow<List<String>> = _logLines

    // Held across states
    private var scannedDevices: List<TvDevice> = emptyList()
    private var selectedDevice: TvDevice? = null
    private var selectedFileBytes: ByteArray? = null
    private var selectedFileName: String = ""

    val localIp: String by lazy { NetworkService.getLocalIpAddress(application) }

    fun scanNetwork() {
        viewModelScope.launch {
            _uiState.value = AppUiState.Scanning
            log("Scanning network for Tizen TVs…")
            try {
                val devices = withContext(Dispatchers.IO) {
                    NetworkService.findTizenTvs(getApplication())
                }
                scannedDevices = devices
                if (devices.isEmpty()) {
                    log("No TVs found.")
                    _uiState.value = AppUiState.NoDevicesFound
                } else {
                    log("Found ${devices.size} TV(s).")
                    _uiState.value = AppUiState.DevicesFound(devices)
                }
            } catch (e: Exception) {
                log("Scan error: ${e.message}")
                _uiState.value = AppUiState.Error("Scan failed: ${e.message}")
            }
        }
    }

    fun connectManualIp(ip: String) {
        viewModelScope.launch {
            _uiState.value = AppUiState.Scanning
            log("Connecting to $ip…")
            try {
                val device = withContext(Dispatchers.IO) {
                    NetworkService.validateManualAddress(ip)
                }
                if (device == null) {
                    log("Could not connect to $ip")
                    _uiState.value = AppUiState.NoDevicesFound
                } else {
                    scannedDevices = listOf(device)
                    log("Connected to ${device.displayName}")
                    _uiState.value = AppUiState.DevicesFound(listOf(device))
                }
            } catch (e: Exception) {
                log("Connection error: ${e.message}")
                _uiState.value = AppUiState.Error("Connect failed: ${e.message}")
            }
        }
    }

    fun onFileSelected(context: Context, uri: Uri) {
        viewModelScope.launch {
            try {
                val bytes = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.readBytes()
                        ?: throw Exception("Cannot read file")
                }
                selectedFileBytes = bytes
                selectedFileName = uri.lastPathSegment ?: "app.wgt"
                log("File selected: $selectedFileName (${bytes.size / 1024} KB)")
                val devs = scannedDevices
                if (devs.isNotEmpty()) {
                    _uiState.value = AppUiState.Ready(devs, selectedFileName, bytes)
                }
            } catch (e: Exception) {
                log("File error: ${e.message}")
                _uiState.value = AppUiState.Error("File read failed: ${e.message}")
            }
        }
    }

    fun selectDevice(device: TvDevice) {
        selectedDevice = device
        // Disconnect unused devices
        viewModelScope.launch(Dispatchers.IO) {
            scannedDevices.filter { it != device }.forEach {
                try { it.sdbDevice.disconnect() } catch (_: Exception) {}
            }
        }
    }

    fun startInstall(device: TvDevice, auth: SamsungAuth?) {
        val bytes = selectedFileBytes ?: return
        selectedDevice = device
        viewModelScope.launch {
            try {
                _uiState.value = AppUiState.CheckingInstalled("Checking existing installation…")
                log("Checking if app is already installed…")

                val installer = TizenInstaller(getApplication(), bytes, device)

                val alreadyInstalled = withContext(Dispatchers.IO) {
                    installer.isAppAlreadyInstalled()
                }

                if (alreadyInstalled) {
                    val pkgId = installer.packageId ?: "unknown"
                    log("App $pkgId is already installed.")
                    _uiState.value = AppUiState.NeedsUninstall(pkgId, scannedDevices, selectedFileName, bytes)
                    return@launch
                }

                doInstall(installer, auth)
            } catch (e: Exception) {
                log("Error: ${e.message}")
                _uiState.value = AppUiState.Error(e.message ?: "Unknown error")
            }
        }
    }

    fun uninstallThenInstall(device: TvDevice, auth: SamsungAuth?) {
        val bytes = selectedFileBytes ?: return
        viewModelScope.launch {
            try {
                val installer = TizenInstaller(getApplication(), bytes, device)
                _uiState.value = AppUiState.Uninstalling
                log("Uninstalling…")
                withContext(Dispatchers.IO) {
                    installer.uninstallApp { progress ->
                        log("Uninstall: ${progress.toInt()}%")
                    }
                }
                log("Uninstall complete.")
                doInstall(installer, auth)
            } catch (e: Exception) {
                log("Error: ${e.message}")
                _uiState.value = AppUiState.Error(e.message ?: "Unknown error")
            }
        }
    }

    fun skipUninstallAndInstall(device: TvDevice, auth: SamsungAuth?) {
        val bytes = selectedFileBytes ?: return
        viewModelScope.launch {
            try {
                val installer = TizenInstaller(getApplication(), bytes, device)
                doInstall(installer, auth)
            } catch (e: Exception) {
                log("Error: ${e.message}")
                _uiState.value = AppUiState.Error(e.message ?: "Unknown error")
            }
        }
    }

    private suspend fun doInstall(installer: TizenInstaller, auth: SamsungAuth?) {
        _uiState.value = AppUiState.Signing
        log("Checking if signing is required…")
        withContext(Dispatchers.IO) {
            installer.signPackageIfNecessary(auth)
        }
        log("Uploading file…")
        _uiState.value = AppUiState.Uploading(0f)
        withContext(Dispatchers.IO) {
            installer.installApp(
                onUploadProgress = { p ->
                    _uiState.value = AppUiState.Uploading(p.toFloat())
                    if (p.toInt() % 10 == 0) log("Upload: ${p.toInt()}%")
                },
                onInstallProgress = { p ->
                    _uiState.value = AppUiState.Installing(uploadDone = true, installProgress = p.toFloat())
                    if (p.toInt() % 10 == 0) log("Install: ${p.toInt()}%")
                }
            )
        }
        log("✔ App installed successfully!")
        _uiState.value = AppUiState.Success("App installed successfully!")
    }

    fun reset() {
        _uiState.value = AppUiState.Idle
        selectedFileBytes = null
        selectedFileName = ""
        selectedDevice = null
        scannedDevices = emptyList()
        _logLines.value = emptyList()
    }

    private fun log(msg: String) {
        _logLines.value = _logLines.value + msg
    }
}
