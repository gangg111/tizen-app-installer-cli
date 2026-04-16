package com.tizen.installer.signing

import com.google.gson.annotations.SerializedName
import org.json.JSONObject

/**
 * Samsung OAuth authentication response. Matches C# SamsungAuth record.
 */
data class SamsungAuth(
    val accessToken: String,
    val tokenType: String,
    val userId: String,
    val inputEmailID: String? = null,
    val accessTokenExpiresIn: String? = null,
    val refreshToken: String? = null,
    val refreshTokenExpiresIn: String? = null,
    val clientId: String? = null,
    val apiServerUrl: String? = null,
    val authServerUrl: String? = null,
    val close: Boolean = false,
    val closedAction: String? = null,
    val state: String? = null
) {
    companion object {
        fun fromJson(json: String): SamsungAuth {
            val obj = JSONObject(json)
            return SamsungAuth(
                accessToken = obj.optString("access_token"),
                tokenType = obj.optString("token_type", "TOKEN"),
                userId = obj.optString("userId"),
                inputEmailID = obj.optString("inputEmailID").takeIf { it.isNotEmpty() },
                accessTokenExpiresIn = obj.optString("access_token_expires_in").takeIf { it.isNotEmpty() },
                refreshToken = obj.optString("refresh_token").takeIf { it.isNotEmpty() },
                refreshTokenExpiresIn = obj.optString("refresh_token_expires_in").takeIf { it.isNotEmpty() },
                clientId = obj.optString("client_id").takeIf { it.isNotEmpty() },
                apiServerUrl = obj.optString("api_server_url").takeIf { it.isNotEmpty() },
                authServerUrl = obj.optString("auth_server_url").takeIf { it.isNotEmpty() },
                close = obj.optBoolean("close", false),
                closedAction = obj.optString("closedAction").takeIf { it.isNotEmpty() },
                state = obj.optString("state").takeIf { it.isNotEmpty() }
            )
        }
    }
}
