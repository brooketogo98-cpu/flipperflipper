# Stitch RAT - Real-Time Web Interface

## Overview
Stitch is a Remote Administration Tool (RAT) with both command-line and web interfaces. This project delivers a real-time web interface providing full functionality for managing and interacting with connected targets. The application has undergone significant security hardening, addressing critical vulnerabilities to achieve production readiness. It offers a graphical dashboard for monitoring connections, executing commands, and managing files on remote systems, serving as a user-friendly alternative to the command-line interface.

## User Preferences
- I want iterative development.
- Ask before making major changes.

## System Architecture
The web interface (`web_app_real.py`) runs as a standalone process, integrating a `stitch_server` instance in a background thread. The server listens on port 4040 for target connections, while the Flask web server operates on port 5000 for the UI. Both share the same `stitch_server` instance within the process, accessing shared data structures like `server.inf_sock` for connection status.

**UI/UX Decisions:**
- Modern, responsive dashboard design with a dark theme.
- Visual indicators for online/offline status.
- Click-to-select functionality for connections.
- WebSocket-based real-time updates for connections and logs, refreshing every 5 seconds.

**Technical Implementations & Feature Specifications:**
- **Real-time Connection Tracking:** Displays actual online/offline status of targets from socket connections, not simulated data.
- **Command Execution:** Supports all 70+ Stitch commands, sending them via `stitch_lib` to targets and displaying real responses. Includes organized command categories and custom command input.
- **File Management:** Browsing and downloading of files from targets.
- **Debug Logging:** Real-time log streaming via WebSocket with filtering capabilities.
- **Security Features:**
    - Environment variable-based credentials (`STITCH_ADMIN_USER`, `STITCH_ADMIN_PASSWORD`) with 12+ character enforcement.
    - Rate limiting using Flask-Limiter for login attempts (5 per 15 min) and API throttling.
    - Secured CORS policy, rejecting wildcards and defaulting to localhost, configurable for production.
    - HTTPS support with auto-generated 4096-bit RSA certificates or custom certificates.
    - Debug mode disabled by default for production safety.
    - Session-based authentication, CSRF protection, and AES encryption for target communication.

**System Design Choices:**
- Flask with Flask-SocketIO for real-time capabilities.
- Eventlet for asynchronous task handling.
- Werkzeug for security utilities (e.g., password hashing).
- Thread-safe access to the shared `stitch_server` instance using locks.
- The web interface and CLI use the same underlying Stitch server code and AES encryption, accepting connections on port 4040.

## External Dependencies
- **Flask**: Web framework for building the application.
- **Flask-SocketIO**: Enables real-time, two-way communication via WebSockets.
- **Flask-Limiter**: Implements rate limiting for API endpoints and login attempts.
- **Eventlet**: Asynchronous I/O library for concurrent operations.
- **Werkzeug**: WSGI utility library, used for security features like password hashing.
- **OpenSSL**: Required for HTTPS certificate generation and management.
- **Python 3.8+**: Minimum required Python version.