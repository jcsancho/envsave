// envsave-touchid — keeps the EnvSave master password in the macOS Keychain
// and releases it only after Touch ID (or the Mac login password).
//
// The keychain item is created by this binary, so only this binary can read
// it without a macOS confirmation dialog. Agents running `security` get a
// dialog they cannot answer, and running this helper triggers Touch ID.
//
// Usage:
//   envsave-touchid store <account>          password on stdin
//   envsave-touchid get <account> <reason>   password on stdout after auth
//   envsave-touchid delete <account>
//   envsave-touchid status <account>
//
// Exit codes: 0 ok, 1 error, 2 no stored password, 3 authentication failed/cancelled.

import Foundation
import LocalAuthentication
import Security

let service = "com.envsave.master-password"

func fail(_ message: String, _ code: Int32) -> Never {
  FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
  exit(code)
}

func baseQuery(_ account: String) -> [String: Any] {
  [kSecClass as String: kSecClassGenericPassword,
   kSecAttrService as String: service,
   kSecAttrAccount as String: account]
}

func authenticate(_ reason: String) -> Bool {
  let context = LAContext()
  var error: NSError?
  // deviceOwnerAuthentication = Touch ID, falling back to the Mac login password.
  guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return false }
  let semaphore = DispatchSemaphore(value: 0)
  var ok = false
  context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
    ok = success
    semaphore.signal()
  }
  semaphore.wait()
  return ok
}

let argv = CommandLine.arguments
guard argv.count >= 3 else { fail("usage: envsave-touchid <store|get|delete|status> <account> [reason]", 1) }
let action = argv[1]
let account = argv[2]

switch action {
case "store":
  let input = FileHandle.standardInput.readDataToEndOfFile()
  guard var password = String(data: input, encoding: .utf8) else { fail("invalid input", 1) }
  if password.hasSuffix("\n") { password.removeLast() }
  guard !password.isEmpty else { fail("empty password", 1) }
  SecItemDelete(baseQuery(account) as CFDictionary)
  var query = baseQuery(account)
  query[kSecValueData as String] = password.data(using: .utf8)!
  query[kSecAttrLabel as String] = "EnvSave master password"
  let status = SecItemAdd(query as CFDictionary, nil)
  guard status == errSecSuccess else { fail("keychain error \(status)", 1) }

case "get":
  let reason = argv.count >= 4 ? argv[3] : "unlock your EnvSave vault"
  var exists = baseQuery(account)
  exists[kSecReturnAttributes as String] = true
  guard SecItemCopyMatching(exists as CFDictionary, nil) == errSecSuccess else { exit(2) }
  guard authenticate(reason) else { exit(3) }
  var query = baseQuery(account)
  query[kSecReturnData as String] = true
  var result: AnyObject?
  let status = SecItemCopyMatching(query as CFDictionary, &result)
  guard status == errSecSuccess, let data = result as? Data else { fail("keychain error \(status)", 1) }
  FileHandle.standardOutput.write(data)

case "delete":
  let status = SecItemDelete(baseQuery(account) as CFDictionary)
  guard status == errSecSuccess || status == errSecItemNotFound else { fail("keychain error \(status)", 1) }

case "status":
  var query = baseQuery(account)
  query[kSecReturnAttributes as String] = true
  exit(SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess ? 0 : 2)

default:
  fail("unknown action \(action)", 1)
}
