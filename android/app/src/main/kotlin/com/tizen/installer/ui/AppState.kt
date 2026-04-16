package com.tizen.installer.ui

import com.tizen.installer.network.TvDevice

sealed class AppUiState {
    object Idle : AppUiState()
    object Scanning : AppUiState()
    data class DevicesFound(val devices: List<TvDevice>) : AppUiState()
    object NoDevicesFound : AppUiState()
    data class Ready(val devices: List<TvDevice>, val filePath: String, val fileBytes: ByteArray) : AppUiState()
    data class CheckingInstalled(val message: String) : AppUiState()
    data class NeedsUninstall(val packageId: String, val devices: List<TvDevice>, val filePath: String, val fileBytes: ByteArray) : AppUiState()
    object Uninstalling : AppUiState()
    object Signing : AppUiState()
    data class Uploading(val progress: Float) : AppUiState()
    data class Installing(val uploadDone: Boolean, val installProgress: Float) : AppUiState()
    data class Success(val message: String) : AppUiState()
    data class Error(val message: String) : AppUiState()
}
