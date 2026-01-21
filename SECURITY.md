# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability
service cloud.firestore {
  match /databases/{database}/documents {
    // Helper function to get user role
    function getRole() {
      return get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role;
    }

    // Resources: Everyone can read, only Staff can upload
    match /resources/{resId} {
      allow read: if request.auth != null;
      allow write: if request.auth != null && getRole() == 'staff';
    }

    // Registrations: Students create, Admins approve
    match /registrations/{regId} {
      allow read, create: if request.auth != null && getRole() == 'student';
      allow update: if request.auth != null && getRole() == 'staff';
    }
  }
}

