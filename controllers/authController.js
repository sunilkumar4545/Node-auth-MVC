// 📁 controllers/authController.js
// Handles register and login logic

const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

exports.getHome = (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'register.html'));
};

exports.register = async (req, res) => {
  try {
    const { name, mobile, password, confirmPassword } = req.body;
    
    // Validation
    if (!name || !mobile || !password || !confirmPassword) {
      return res.status(400).json({ error: "All fields are required" });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match" });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters long" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ mobile });
    if (existingUser) {
      return res.status(400).json({ error: "Mobile number already registered" });
    }

    // Hash password and create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, mobile, password: hashedPassword });
    await user.save();

    res.status(201).json({ 
      message: "User registered successfully",
      user: {
        id: user._id,
        name: user.name,
        mobile: user.mobile
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: "Internal server error" });
  }
};

exports.login = async (req, res) => {
  try {
    const { mobile, password } = req.body; // Changed from name to mobile for consistency
    
    if (!mobile || !password) {
      return res.status(400).json({ error: "Mobile and password are required" });
    }

    // Find user by mobile (consistent with registration)
    const user = await User.findOne({ mobile });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, mobile: user.mobile },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(200).json({
      message: "Login successful",
      token: token,
      redirectUrl: "https://sunilkumar4545.github.io/sunilkumarsodisetty/",
      user: {
        id: user._id,
        name: user.name,
        mobile: user.mobile
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: "Internal server error" });
  }
};
