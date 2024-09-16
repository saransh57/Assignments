import Foundation

class DatabaseManager {
    var db: OpaquePointer?

    init() {
        if sqlite3_open("myDatabase.sqlite", &db) != SQLITE_OK {
            print("Error opening database")
        }
    }

    // MARK: - Vulnerable Examples

    // 1. Basic SQL Injection
    func vulnerableLogin(username: String, password: String) {
        let query = "SELECT * FROM users WHERE username = '\(username)' AND password = '\(password)'"
        // Vulnerable to: admin' --
    }

    // 2. UNION-based Injection
    func vulnerableUnionQuery(id: String) {
        let query = "SELECT name, description FROM products WHERE id = \(id)"
        // Vulnerable to: 1 UNION SELECT username, password FROM users --
    }

    // 3. Blind SQL Injection
    func vulnerableBlindQuery(id: String) {
        let query = "SELECT * FROM users WHERE id = \(id)"
        // Vulnerable to: 1 AND 1=1 or 1 AND 1=2
    }

    // 4. Time-based Blind Injection
    func vulnerableTimeBasedQuery(id: String) {
        let query = "SELECT * FROM users WHERE id = \(id)"
        // Vulnerable to: 1 AND (SELECT CASE WHEN (1=1) THEN sqlite3_sleep(5000) ELSE sqlite3_sleep(0) END)
    }

    // 5. Error-based Injection
    func vulnerableErrorBasedQuery(id: String) {
        let query = "SELECT * FROM users WHERE id = '\(id)'"
        // Vulnerable to: ' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)='1
    }

    // 6. Second-Order Injection
    func vulnerableSecondOrderInjection(username: String) {
        // First, insert potentially malicious data
        let insertQuery = "INSERT INTO users (username) VALUES ('\(username)')"
        // Later, use it in another query
        let selectQuery = "SELECT * FROM users WHERE username = '\(username)'"
        // Vulnerable to stored malicious input
    }

    // 7. Mass Assignment Vulnerability (not strictly SQL Injection, but related)
    func vulnerableMassAssignment(userInput: [String: Any]) {
        var setClause = userInput.map { key, value in "\(key) = '\(value)'" }.joined(separator: ", ")
        let query = "UPDATE users SET \(setClause) WHERE id = 1"
        // Vulnerable to unexpected field updates
    }

    // MARK: - Safe Examples

    // 1. Safe Login Query
    func safeLogin(username: String, password: String) {
        let query = "SELECT * FROM users WHERE username = ? AND password = ?"
        var statement: OpaquePointer?
        if sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK {
            sqlite3_bind_text(statement, 1, username, -1, nil)
            sqlite3_bind_text(statement, 2, password, -1, nil)
            while sqlite3_step(statement) == SQLITE_ROW {
                // Process results...
            }
        }
        sqlite3_finalize(statement)
    }

    // 2. Safe Numeric Input Handling
    func safeNumericQuery(id: String) {
        guard let numericId = Int(id) else {
            print("Invalid input")
            return
        }
        let query = "SELECT * FROM products WHERE id = ?"
        var statement: OpaquePointer?
        if sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK {
            sqlite3_bind_int(statement, 1, Int32(numericId))
            while sqlite3_step(statement) == SQLITE_ROW {
                // Process results...
            }
        }
        sqlite3_finalize(statement)
    }

    // 3. Safe Dynamic Query Building
    func safeDynamicQuery(conditions: [String: Any]) {
        var whereClauses: [String] = []
        var values: [Any] = []
        for (key, value) in conditions {
            whereClauses.append("\(key) = ?")
            values.append(value)
        }
        let whereString = whereClauses.joined(separator: " AND ")
        let query = "SELECT * FROM table WHERE \(whereString)"
        var statement: OpaquePointer?
        if sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK {
            for (index, value) in values.enumerated() {
                bindValue(statement: statement, index: index + 1, value: value)
            }
            while sqlite3_step(statement) == SQLITE_ROW {
                // Process results...
            }
        }
        sqlite3_finalize(statement)
    }

    private func bindValue(statement: OpaquePointer?, index: Int, value: Any) {
        switch value {
        case let stringValue as String:
            sqlite3_bind_text(statement, Int32(index), stringValue, -1, nil)
        case let intValue as Int:
            sqlite3_bind_int(statement, Int32(index), Int32(intValue))
        case let doubleValue as Double:
            sqlite3_bind_double(statement, Int32(index), doubleValue)
        case is NSNull:
            sqlite3_bind_null(statement, Int32(index))
        default:
            print("Unsupported type")
        }
    }
}

// MARK: - Using a Swift SQLite wrapper for added safety

import SQLite // Make sure to include the SQLite.swift library in your project

class SafeSQLiteWrapper {
    let db: Connection

    init() throws {
        db = try Connection("myDatabase.sqlite")
    }

    func safeQuery(username: String) throws {
        let users = Table("users")
        let usernameColumn = Expression<String>("username")
        let query = users.filter(usernameColumn == username)
        for user in try db.prepare(query) {
            print("User: \(user[usernameColumn])")
        }
    }
}

// Usage examples
let dbManager = DatabaseManager()

// Vulnerable usages (DO NOT USE IN PRODUCTION)
dbManager.vulnerableLogin(username: "admin' --", password: "anything")
dbManager.vulnerableUnionQuery(id: "1 UNION SELECT username, password FROM users --")
dbManager.vulnerableBlindQuery(id: "1 AND 1=1")
dbManager.vulnerableTimeBasedQuery(id: "1 AND (SELECT CASE WHEN (1=1) THEN sqlite3_sleep(5000) ELSE sqlite3_sleep(0) END)")
dbManager.vulnerableErrorBasedQuery(id: "' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)='1")
dbManager.vulnerableSecondOrderInjection(username: "admin'; DROP TABLE users; --")
dbManager.vulnerableMassAssignment(userInput: ["username": "newadmin", "is_admin": "true"])

// Safe usages
dbManager.safeLogin(username: "admin' --", password: "anything")
dbManager.safeNumericQuery(id: "1 UNION SELECT username, password FROM users --")
dbManager.safeDynamicQuery(conditions: ["username": "admin' --", "status": "active"])

do {
    let safeWrapper = try SafeSQLiteWrapper()
    try safeWrapper.safeQuery(username: "admin' --")
} catch {
    print("Error: \(error)")
}
