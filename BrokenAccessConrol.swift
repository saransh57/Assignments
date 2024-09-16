// This vulnerability happens when application has no proper access control

// Direct Object Reference
// Non-compliant: Direct object reference without authorization
func getUserData(userId: String) {
    let query = "SELECT * FROM users WHERE id = \(userId)"
    // Fetch user data based on userId without any access check
}

// Compliant: Access control check added
func getUserData(userId: String, currentUser: User) {
    guard currentUser.hasPermission(for: userId) else {
        print("Access denied")
        return
    }
    let query = "SELECT * FROM users WHERE id = \(userId)"
}
// Hardcoded Role-based Access

// Non-compliant: Hardcoded role-based access without dynamic checks
if user.role == "admin" {
    deleteRecord()
}
// Compliant: Dynamically check access control based on permissions
if user.hasPermission(.deleteRecord) {
    deleteRecord()
}

// Insecure API Exposure

// Non-compliant: Exposing sensitive API without access control
func getAllUsers() {
    let query = "SELECT * FROM users"
    // Returns all user data without authentication check
}
// Compliant: Ensure only authorized users can access the API
func getAllUsers(currentUser: User) {
    guard currentUser.isAdmin else {
        print("Unauthorized access")
        return
    }
    let query = "SELECT * FROM users"
}

// Exposing Sensitive Data
// Non-compliant: Exposing sensitive data without access checks
func getSensitiveData() -> String {
    return "Sensitive data"
}
// Compliant: Check user permission before returning sensitive data
func getSensitiveData(currentUser: User) -> String? {
    guard currentUser.hasPermission(.viewSensitiveData) else {
        return nil
    }
    return "Sensitive data"
}

// Overly Permissive Access Control
// Non-compliant: Allowing access without properly limiting permissions
func updateProfile(user: User) {
    // No access control checks, anyone can update any profile
    user.profile = "Updated"
}
// Compliant: Ensure only the user or admin can update profile
func updateProfile(currentUser: User, user: User) {
    guard currentUser.isAdmin || currentUser.id == user.id else {
        print("Access denied")
        return
    }
    user.profile = "Updated"
}

// Lack of Ownership Check
// Non-compliant: No ownership check before modifying the resource
func deletePost(postId: String) {
    let query = "DELETE FROM posts WHERE id = \(postId)"
}
// Compliant: Ensure user owns the post before deleting
func deletePost(postId: String, currentUser: User) {
    guard currentUser.ownsPost(postId) else {
        print("You do not own this post")
        return
    }
    let query = "DELETE FROM posts WHERE id = \(postId)"
}

// Public Endpoint Without Authorization
// Non-compliant: Public endpoint without authorization
func publicEndpoint() {
    // Publicly accessible without any checks
}
// Compliant: Restrict public access to only authorized users
func publicEndpoint(currentUser: User) {
    guard currentUser.isAuthenticated else {
        print("Unauthorized access")
        return
    }
}

// Privilege Escalation
// Non-compliant: Users can escalate their privilege by modifying their role
func escalatePrivileges(user: User) {
    user.role = "admin"
}
// Compliant: Only an admin can modify user roles
func escalatePrivileges(admin: User, user: User) {
    guard admin.isAdmin else {
        print("You are not authorized to change roles")
        return
    }
    user.role = "admin"
}

// Unauthenticated API Call
// Non-compliant: API endpoint without authentication
func apiCall() {
    // No authentication check
}

// Compliant: Ensure the user is authenticated before calling the API
func apiCall(currentUser: User) {
    guard currentUser.isAuthenticated else {
        print("Authentication required")
        return
    }
}

//Improper Access to Admin Functionality
// Non-compliant: Non-admin user accessing admin functionality
func adminFunction() {
    // No check for admin role
}
// Compliant: Ensure only admin can access the functionality
func adminFunction(currentUser: User) {
    guard currentUser.isAdmin else {
        print("Admin access required")
        return
    }
}
