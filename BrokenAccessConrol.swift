// This vulnerability happens when application has no proper access control

import Foundation

class AccessControlExamples {

    // 1. Direct Object Reference
    // Vulnerable: Direct object reference without authorization
    func vulnerableGetUserData(userId: String) {
        let query = "SELECT * FROM users WHERE id = \(userId)"
        // Fetch user data based on userId without any access check
    }
    
    // Compliant: Access control check added
    func compliantGetUserData(userId: String, currentUser: User) {
        guard currentUser.hasPermission(for: userId) else {
            print("Access denied")
            return
        }
        let query = "SELECT * FROM users WHERE id = \(userId)"
        // Fetch user data after access check
    }

    // 2. Hardcoded Role-based Access
    // Vulnerable: Hardcoded role-based access without dynamic checks
    func vulnerableRoleBasedAccess(user: User) {
        if user.role == "admin" {
            deleteRecord()
        }
    }

    // Compliant: Dynamically check access control based on permissions
    func compliantRoleBasedAccess(user: User) {
        if user.hasPermission(.deleteRecord) {
            deleteRecord()
        }
    }

    // 3. Insecure API Exposure
    // Vulnerable: Exposing sensitive API without access control
    func vulnerableGetAllUsers() {
        let query = "SELECT * FROM users"
        // Returns all user data without authentication check
    }

    // Compliant: Ensure only authorized users can access the API
    func compliantGetAllUsers(currentUser: User) {
        guard currentUser.isAdmin else {
            print("Unauthorized access")
            return
        }
        let query = "SELECT * FROM users"
        // Returns data after authorization check
    }

    // 4. Exposing Sensitive Data
    // Vulnerable: Exposing sensitive data without access checks
    func vulnerableGetSensitiveData() -> String {
        return "Sensitive data"
        // Returns sensitive data without any check
    }

    // Compliant: Check user permission before returning sensitive data
    func compliantGetSensitiveData(currentUser: User) -> String? {
        guard currentUser.hasPermission(.viewSensitiveData) else {
            return nil
        }
        return "Sensitive data"
    }

    // 5. Overly Permissive Access Control
    // Vulnerable: Allowing access without properly limiting permissions
    func vulnerableUpdateProfile(user: User) {
        user.profile = "Updated"
        // No access control checks, anyone can update any profile
    }

    // Compliant: Ensure only the user or admin can update profile
    func compliantUpdateProfile(currentUser: User, user: User) {
        guard currentUser.isAdmin || currentUser.id == user.id else {
            print("Access denied")
            return
        }
        user.profile = "Updated"
    }

    // 6. Lack of Ownership Check
    // Vulnerable: No ownership check before modifying the resource
    func vulnerableDeletePost(postId: String) {
        let query = "DELETE FROM posts WHERE id = \(postId)"
        // Deleting post without checking ownership
    }

    // Compliant: Ensure user owns the post before deleting
    func compliantDeletePost(postId: String, currentUser: User) {
        guard currentUser.ownsPost(postId) else {
            print("You do not own this post")
            return
        }
        let query = "DELETE FROM posts WHERE id = \(postId)"
        // Post deleted after ownership verification
    }

    // 7. Public Endpoint Without Authorization
    // Vulnerable: Public endpoint without authorization
    func vulnerablePublicEndpoint() {
        // Publicly accessible without any checks
    }

    // Compliant: Restrict public access to only authorized users
    func compliantPublicEndpoint(currentUser: User) {
        guard currentUser.isAuthenticated else {
            print("Unauthorized access")
            return
        }
        // Public endpoint accessed after authentication check
    }

    // 8. Privilege Escalation
    // Vulnerable: Users can escalate their privilege by modifying their role
    func vulnerableEscalatePrivileges(user: User) {
        user.role = "admin"
        // Any user can escalate to admin role
    }

    // Compliant: Only an admin can modify user roles
    func compliantEscalatePrivileges(admin: User, user: User) {
        guard admin.isAdmin else {
            print("You are not authorized to change roles")
            return
        }
        user.role = "admin"
    }

    // 9. Unauthenticated API Call
    // Vulnerable: API endpoint without authentication
    func vulnerableApiCall() {
        // No authentication check
    }

    // Compliant: Ensure the user is authenticated before calling the API
    func compliantApiCall(currentUser: User) {
        guard currentUser.isAuthenticated else {
            print("Authentication required")
            return
        }
        // API call after authentication check
    }

    // 10. Improper Access to Admin Functionality
    // Vulnerable: Non-admin user accessing admin functionality
    func vulnerableAdminFunction() {
        // No check for admin role
    }

    // Compliant: Ensure only admin can access the functionality
    func compliantAdminFunction(currentUser: User) {
        guard currentUser.isAdmin else {
            print("Admin access required")
            return
        }
        // Admin functionality executed after role verification
    }

    // Helper Functions
    func deleteRecord() {
        print("Record deleted")
    }
}

class User {
    var id: String
    var role: String
    var profile: String
    var isAuthenticated: Bool
    var isAdmin: Bool

    init(id: String, role: String, profile: String, isAuthenticated: Bool, isAdmin: Bool) {
        self.id = id
        self.role = role
        self.profile = profile
        self.isAuthenticated = isAuthenticated
        self.isAdmin = isAdmin
    }

    func hasPermission(_ permission: Permission) -> Bool {
        // Assume this function checks user's permissions
        return true
    }

    func ownsPost(_ postId: String) -> Bool {
        // Assume this function checks if the user owns the post
        return true
    }

    func hasPermission(for userId: String) -> Bool {
        // Assume this function checks if the user has permission to access another user's data
        return true
    }
}

enum Permission {
    case deleteRecord
    case viewSensitiveData
}
