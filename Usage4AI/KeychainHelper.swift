import Foundation
import Security

enum KeychainError: Error {
    case itemNotFound
    case unexpectedData
    case unhandledError(status: OSStatus)
    case jsonParsingError
    case tokenNotFound
}

struct KeychainHelper {
    private static let claudeCodeService = "Claude Code-credentials"
    private static let ownService = "Usage4AI-token"
    private static let account = "oauth-token"

    /// Get OAuth Token (prioritize reading from own keychain to avoid repeated password prompts)
    static func getOAuthToken() throws -> String {
        // 1. Try reading from own keychain first
        if let cachedToken = try? getOwnToken() {
            return cachedToken
        }

        // 2. Read from Claude Code's keychain
        let token = try getClaudeCodeToken()

        // 3. Save to own keychain (no password prompt next time)
        try? saveOwnToken(token)

        return token
    }

    /// Read token from own keychain
    private static func getOwnToken() throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: ownService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let token = String(data: data, encoding: .utf8) else {
            throw KeychainError.itemNotFound
        }

        return token
    }

    /// Save token to own keychain
    private static func saveOwnToken(_ token: String) throws {
        guard let tokenData = token.data(using: .utf8) else {
            throw KeychainError.unexpectedData
        }

        // Try to delete existing token first
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: ownService,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // Add new token
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: ownService,
            kSecAttrAccount as String: account,
            kSecValueData as String: tokenData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status: status)
        }
    }

    /// Clear own token cache (call when token becomes invalid)
    static func clearCachedToken() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: ownService,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Read token directly from Claude Code's keychain (bypasses own cache)
    static func getClaudeCodeTokenDirectly() throws -> String {
        return try getClaudeCodeToken()
    }

    /// Read token from Claude Code's keychain
    private static func getClaudeCodeToken() throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: claudeCodeService,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status != errSecItemNotFound else {
            throw KeychainError.itemNotFound
        }

        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status: status)
        }

        guard let data = result as? Data else {
            throw KeychainError.unexpectedData
        }

        guard let jsonString = String(data: data, encoding: .utf8) else {
            throw KeychainError.unexpectedData
        }

        return try extractAccessToken(from: jsonString)
    }

    private static func extractAccessToken(from jsonString: String) throws -> String {
        guard let jsonData = jsonString.data(using: .utf8) else {
            throw KeychainError.jsonParsingError
        }

        guard let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            throw KeychainError.jsonParsingError
        }

        guard let claudeAiOauth = json["claudeAiOauth"] as? [String: Any],
              let accessToken = claudeAiOauth["accessToken"] as? String else {
            throw KeychainError.tokenNotFound
        }

        return accessToken
    }
}
