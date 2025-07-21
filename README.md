# NODE.JS AUTHENTICATION PROJECT - COMPLETE GUIDE

## 📋 PROJECT OVERVIEW

This is a complete authentication system built with Node.js that allows users to:

1. Register (create an account)
2. Login (authenticate)
3. Automatically redirect to a portfolio website after successful login

The project uses modern web technologies and follows best practices for security
and user experience.

## 🏗️ PROJECT STRUCTURE

```
📁 Project Root (e:\New folder\)
├── 📄 app.js                    (Main server file - Entry point)
├── 📄 package.json              (Project configuration & dependencies)
├── 📄 .env                      (Environment variables - Secret data)
├── 📁 controllers/              (Business logic folder)
│   └── 📄 authController.js     (Authentication logic)
├── 📁 models/                   (Database models folder)
│   └── 📄 User.js               (User database schema)
├── 📁 routes/                   (URL routing folder)
│   └── 📄 authRoutes.js         (Authentication routes)
└── 📁 public/                   (Frontend files folder)
    ├── 📄 register.html         (Registration page)
    └── 📄 login.html            (Login page)
```

## 📦 PACKAGES USED (DEPENDENCIES)

### 1. EXPRESS.JS (^5.1.0)

- **Purpose**: Web framework for Node.js
- **What it does**: Creates the web server, handles HTTP requests/responses
- **Why needed**: Makes it easy to build web applications and APIs

### 2. MONGOOSE (^8.16.4)

- **Purpose**: MongoDB object modeling for Node.js
- **What it does**: Connects to MongoDB database, defines data schemas
- **Why needed**: Provides easy way to work with MongoDB database

### 3. BCRYPTJS (^3.0.2)

- **Purpose**: Password hashing library
- **What it does**: Encrypts passwords before storing in database
- **Why needed**: Security - never store plain text passwords

### 4. JSONWEBTOKEN (^9.0.0)

- **Purpose**: JWT (JSON Web Token) implementation
- **What it does**: Creates secure tokens for user authentication
- **Why needed**: Stateless authentication, secure user sessions

### 5. DOTENV (^17.2.0)

- **Purpose**: Environment variables loader
- **What it does**: Loads configuration from .env file
- **Why needed**: Keep sensitive data (passwords, API keys) secure

### 6. NODEMON (^3.1.10) - Development Only

- **Purpose**: Development tool
- **What it does**: Automatically restarts server when files change
- **Why needed**: Makes development faster - no manual server restarts

## 🔧 FILE-BY-FILE EXPLANATION

### 1. 📄 package.json

**PURPOSE**: Project configuration file

**WHAT IT CONTAINS**:

- Project metadata (name, version, description)
- Dependencies list (what packages to install)
- Scripts for running the application
- Entry point definition

**KEY SECTIONS**:

```json
{
  "name": "new-folder", // Project name
  "main": "app.js", // Entry point file
  "scripts": {
    "start": "nodemon app.js" // Command to start server
  },
  "dependencies": {
    // Required packages
    "express": "^5.1.0",
    "mongoose": "^8.16.4"
    // ... other packages
  }
}
```

**HOW IT WORKS**:

- When you run "npm install", it reads this file and installs all dependencies
- When you run "npm start", it executes the start script
- Node.js uses "main" to know which file to run first

### 2. 📄 .env

**PURPOSE**: Store sensitive configuration data

**WHAT IT CONTAINS**:

```
MONGO_URI=mongodb+srv://auth:abcd@cluster0.xvx9qbi.mongodb.net/auth
PORT=3000
JWT_SECRET=mySecretJWTKey123456789AuthAppSecure2024
```

**EXPLANATION**:

- MONGO_URI: Connection string for MongoDB database
- PORT: Which port the server runs on (3000)
- JWT_SECRET: Secret key for creating secure tokens

**WHY SEPARATE FILE**:

- Keep sensitive data out of main code
- Different environments can have different values
- Security best practice

### 3. 📄 app.js (MAIN SERVER FILE)

**PURPOSE**: The heart of the application - sets up and starts the web server

**STEP-BY-STEP BREAKDOWN**:

```javascript
// Import required packages
const express = require("express"); // Web framework
const path = require("path"); // File path utilities
const mongoose = require("mongoose"); // Database connection
require("dotenv").config(); // Load environment variables
const authRoutes = require("./routes/authRoutes"); // Import routes

// Create Express application
const app = express();
const PORT = process.env.PORT || 3000; // Use env PORT or default 3000

// MIDDLEWARE SETUP (runs before route handlers)
app.use(express.json()); // Parse JSON requests
app.use(express.urlencoded({ extended: true })); // Parse form data
app.use(express.static(path.join(__dirname, "public"))); // Serve static files

// ROUTES SETUP
app.use("/", authRoutes); // All routes handled by authRoutes

// DATABASE CONNECTION & SERVER START
mongoose
  .connect(process.env.MONGO_URI) // Connect to MongoDB
  .then(() => {
    console.log("Connected to MongoDB");
    app.listen(PORT, () =>
      console.log(`Server running on http://localhost:${PORT}`)
    );
  })
  .catch((err) => console.error("MongoDB connection failed:", err));
```

**WHAT EACH PART DOES**:

- **MIDDLEWARE**: Code that runs before your route handlers

  - express.json(): Allows server to understand JSON data
  - express.urlencoded(): Allows server to understand form data
  - express.static(): Serves HTML, CSS, JS files from 'public' folder

- **ROUTES**: Defines what happens when users visit different URLs
- **DATABASE**: Connects to MongoDB for data storage
- **SERVER**: Starts listening for incoming requests

### 4. 📄 models/User.js

**PURPOSE**: Define the structure of user data in the database

```javascript
const mongoose = require("mongoose");

// Define what a user looks like in the database
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true }, // User's full name (required)
    mobile: { type: String, required: true, unique: true }, // Phone (required, unique)
    password: { type: String, required: true }, // Encrypted password (required)
  },
  {
    timestamps: true, // Automatically add createdAt and updatedAt fields
  }
);

module.exports = mongoose.model("User", userSchema);
```

**WHAT THIS DOES**:

- Creates a "blueprint" for user data
- Ensures data validation (required fields)
- Prevents duplicate mobile numbers (unique: true)
- Automatically tracks when users are created/updated
- Exports the model so other files can use it

**VALIDATION RULES**:

- name: Must be provided, must be text
- mobile: Must be provided, must be text, must be unique
- password: Must be provided, must be text

### 5. 📄 routes/authRoutes.js

**PURPOSE**: Define URL endpoints and connect them to controller functions

```javascript
const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");

// Define routes (URL patterns) and what functions handle them
router.get("/", authController.getHome); // GET / -> show register page
router.post("/register", authController.register); // POST /register -> handle registration
router.post("/login", authController.login); // POST /login -> handle login

module.exports = router;
```

**ROUTE EXPLANATIONS**:

- GET /: When user visits homepage, show register page
- POST /register: When form is submitted to /register, run register function
- POST /login: When form is submitted to /login, run login function

**HTTP METHODS**:

- GET: Retrieve/display data (show pages)
- POST: Send/submit data (form submissions)

### 6. 📄 controllers/authController.js

**PURPOSE**: Contains the business logic - what actually happens for each route

```javascript
const User = require("../models/User"); // Import User model
const bcrypt = require("bcryptjs"); // For password encryption
const jwt = require("jsonwebtoken"); // For creating tokens
const path = require("path"); // For file paths

// FUNCTION 1: Show register page when user visits homepage
exports.getHome = (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "register.html"));
};

// FUNCTION 2: Handle user registration
exports.register = async (req, res) => {
  try {
    // Extract data from request body
    const { name, mobile, password, confirmPassword } = req.body;

    // VALIDATION CHECKS
    if (!name || !mobile || !password || !confirmPassword) {
      return res.status(400).json({ error: "All fields are required" });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters long" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ mobile });
    if (existingUser) {
      return res
        .status(400)
        .json({ error: "Mobile number already registered" });
    }

    // ENCRYPT PASSWORD (never store plain text passwords!)
    const hashedPassword = await bcrypt.hash(password, 10);

    // CREATE AND SAVE NEW USER
    const user = new User({ name, mobile, password: hashedPassword });
    await user.save();

    // SEND SUCCESS RESPONSE
    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: user._id,
        name: user.name,
        mobile: user.mobile,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};

// FUNCTION 3: Handle user login
exports.login = async (req, res) => {
  try {
    const { mobile, password } = req.body;

    // VALIDATION
    if (!mobile || !password) {
      return res
        .status(400)
        .json({ error: "Mobile and password are required" });
    }

    // FIND USER IN DATABASE
    const user = await User.findOne({ mobile });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // VERIFY PASSWORD
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // CREATE JWT TOKEN (for maintaining user session)
    const token = jwt.sign(
      { userId: user._id, mobile: user.mobile }, // Data to include in token
      process.env.JWT_SECRET, // Secret key for signing
      { expiresIn: "24h" } // Token expires in 24 hours
    );

    // SEND SUCCESS RESPONSE WITH REDIRECT URL
    res.status(200).json({
      message: "Login successful",
      token: token,
      redirectUrl: "https://sunilkumar4545.github.io/sunilkumarsodisetty/",
      user: {
        id: user._id,
        name: user.name,
        mobile: user.mobile,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};
```

**KEY CONCEPTS**:

- **ASYNC/AWAIT**: Handles database operations that take time
- **PASSWORD HASHING**: bcrypt.hash() encrypts passwords
- **PASSWORD VERIFICATION**: bcrypt.compare() checks if password is correct
- **JWT TOKENS**: Secure way to maintain user sessions
- **ERROR HANDLING**: try/catch blocks handle errors gracefully

### 7. 📄 public/register.html

**PURPOSE**: Frontend registration form

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Register - Auth App</title>
    <style>
      /* CSS styles for professional appearance */
      body {
        font-family: sans-serif;
        margin: 50px auto;
        max-width: 400px;
        padding: 20px;
        border: 1px solid #ccc;
        border-radius: 8px;
        background-color: #f9f9f9;
      }
      /* ... more CSS for styling */
    </style>
  </head>
  <body>
    <h1>Register</h1>

    <!-- REGISTRATION FORM -->
    <form id="register-form">
      <input type="text" name="name" placeholder="Full Name" required />
      <input type="tel" name="mobile" placeholder="Mobile Number" required />
      <input
        type="password"
        name="password"
        placeholder="Password (min 6 chars)"
        required
      />
      <input
        type="password"
        name="confirmPassword"
        placeholder="Confirm Password"
        required
      />
      <button type="submit">Register</button>
    </form>

    <!-- MESSAGE DISPLAY AREA -->
    <div id="message" class="message" style="display: none;"></div>

    <!-- NAVIGATION -->
    <div class="nav-links">
      <a href="/login.html">Already have an account? Login</a>
    </div>

    <script>
      // JAVASCRIPT FOR FORM HANDLING
      document
        .getElementById("register-form")
        .addEventListener("submit", async (e) => {
          e.preventDefault(); // Prevent default form submission

          // COLLECT FORM DATA
          const formData = new FormData(e.target);
          const data = {
            name: formData.get("name"),
            mobile: formData.get("mobile"),
            password: formData.get("password"),
            confirmPassword: formData.get("confirmPassword"),
          };

          const messageDiv = document.getElementById("message");
          messageDiv.style.display = "none";

          try {
            // SEND DATA TO SERVER
            const response = await fetch("/register", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify(data),
            });

            const result = await response.json();

            messageDiv.style.display = "block";

            if (response.ok) {
              // SUCCESS: Show success message and redirect
              messageDiv.className = "message success";
              messageDiv.textContent = result.message;
              e.target.reset(); // Clear form

              // Redirect to login after 2 seconds
              setTimeout(() => {
                window.location.href = "/login.html";
              }, 2000);
            } else {
              // ERROR: Show error message
              messageDiv.className = "message error";
              messageDiv.textContent = result.error || "Registration failed";
            }
          } catch (error) {
            // NETWORK ERROR: Show network error message
            messageDiv.style.display = "block";
            messageDiv.className = "message error";
            messageDiv.textContent = "Network error. Please try again.";
          }
        });
    </script>
  </body>
</html>
```

**HOW IT WORKS**:

1. User fills out form with name, mobile, password, confirm password
2. When submitted, JavaScript prevents default submission
3. JavaScript collects form data and converts to JSON
4. Sends AJAX request to /register endpoint
5. Displays success/error message based on response
6. If successful, redirects to login page after 2 seconds

### 8. 📄 public/login.html

**PURPOSE**: Frontend login form

Similar structure to register.html but with login-specific functionality:

```html
<form id="login-form">
  <input type="tel" name="mobile" placeholder="Mobile Number" required />
  <input type="password" name="password" placeholder="Password" required />
  <button type="submit">Login</button>
</form>
```

**JAVASCRIPT DIFFERENCES**:

- Only collects mobile and password
- Sends to /login endpoint
- On success, stores JWT token and redirects to portfolio
- Shows countdown before redirect

**KEY JAVASCRIPT FEATURES**:

```javascript
// Store authentication data
localStorage.setItem("authToken", result.token);
localStorage.setItem("userInfo", JSON.stringify(result.user));

// Redirect to portfolio
setTimeout(() => {
  if (result.redirectUrl) {
    window.location.href = result.redirectUrl;
  }
}, 2000);
```

## 🔄 HOW FILES CONNECT TO EACH OTHER

**DATA FLOW DIAGRAM**:

```
Browser          →    app.js           →    authRoutes.js    →    authController.js
(register.html)       (Web Server)          (URL Routing)         (Business Logic)
                                                                          ↓
Database         ←    User.js           ←    mongoose          ←    (Save/Find Users)
(MongoDB)             (Data Model)          (Database Layer)
```

**STEP-BY-STEP CONNECTION**:

1. **USER VISITS WEBSITE**
   Browser → http://localhost:3000 → app.js → authRoutes.js → authController.getHome() → register.html

2. **USER SUBMITS REGISTRATION**
   register.html → JavaScript fetch() → app.js → authRoutes.js → authController.register() → User.js → MongoDB

3. **USER SUBMITS LOGIN**
   login.html → JavaScript fetch() → app.js → authRoutes.js → authController.login() → User.js → MongoDB

4. **SUCCESSFUL LOGIN**
   authController.login() → JSON response → login.html → JavaScript redirect → Portfolio website

**FILE RELATIONSHIPS**:

```
📄 app.js
├── Imports: express, mongoose, authRoutes, dotenv
├── Uses: .env for configuration
└── Serves: public/ folder files

📄 authRoutes.js
├── Imports: express, authController
└── Defines: URL patterns and handlers

📄 authController.js
├── Imports: User model, bcrypt, jsonwebtoken
├── Uses: .env for JWT_SECRET
└── Handles: Registration and login logic

📄 User.js
├── Imports: mongoose
└── Defines: Database schema

📄 register.html & login.html
├── Makes requests to: authRoutes endpoints
├── Receives responses from: authController
└── Displays: User interface
```

## 🔐 SECURITY FEATURES

### 1. PASSWORD HASHING

- Passwords are encrypted with bcrypt before storing
- Salt rounds: 10 (makes hacking harder)
- Original passwords are never stored

### 2. JWT TOKENS

- Stateless authentication
- Tokens expire after 24 hours
- Signed with secret key

### 3. INPUT VALIDATION

- Required field checks
- Password length requirements
- Duplicate user prevention

### 4. ENVIRONMENT VARIABLES

- Sensitive data in .env file
- Database credentials not in code
- JWT secret key protected

## 🚀 HOW TO RUN THE PROJECT

### 1. INSTALL DEPENDENCIES

```bash
npm install
```

### 2. START THE SERVER

```bash
npm start
```

### 3. OPEN BROWSER

```
http://localhost:3000
```

### 4. TEST FUNCTIONALITY

- Register a new user
- Login with credentials
- Get redirected to portfolio

## 📊 DATABASE STRUCTURE

**MONGODB COLLECTION**: users

**DOCUMENT STRUCTURE**:

```json
{
  "_id": "ObjectId(...)", // Unique identifier (auto-generated)
  "name": "John Doe", // User's full name
  "mobile": "1234567890", // Phone number (unique)
  "password": "$2a$10$...", // Encrypted password hash
  "createdAt": "ISODate(...)", // When user registered
  "updatedAt": "ISODate(...)" // When user was last updated
}
```

**INDEXES**:

- \_id: Primary key (automatic)
- mobile: Unique index (prevents duplicates)

## 🔧 TROUBLESHOOTING COMMON ISSUES

### 1. "Cannot connect to MongoDB"

- Check internet connection
- Verify MONGO_URI in .env file
- Ensure MongoDB Atlas cluster is running

### 2. "Internal server error"

- Check terminal for error messages
- Verify all required fields are provided
- Check database connection

### 3. "User already exists"

- Mobile number is already registered
- Try with different mobile number

### 4. "Invalid credentials"

- Wrong mobile number or password
- Check spelling and try again

### 5. Port already in use

- Change PORT in .env file
- Or stop other applications using port 3000

## 🎯 FUTURE ENHANCEMENTS

**POSSIBLE IMPROVEMENTS**:

1. Email verification
2. Password reset functionality
3. User profile management
4. Admin dashboard
5. Rate limiting for security
6. Email notifications
7. OAuth integration (Google, Facebook)
8. Mobile app version

**LEARNING OPPORTUNITIES**:

1. Add unit tests
2. Implement caching with Redis
3. Add API documentation with Swagger
4. Deploy to cloud (Heroku, AWS)
5. Add monitoring and logging
6. Implement microservices architecture

---

## END OF GUIDE

This authentication system demonstrates modern web development practices
including RESTful APIs, secure authentication, database integration, and
responsive frontend design. It's a solid foundation for any web application
requiring user authentication.

For questions or improvements, refer to the official documentation of each
package used in this project.
