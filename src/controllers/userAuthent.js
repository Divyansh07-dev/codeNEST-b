const redisClient = require("../config/redis");
const User = require("../models/user");
const validate = require('../utils/validator');
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const Submission = require("../models/submission");

// Helper function for consistent error response
const sendAuthError = (res) => {
    // 401 Unauthorized for login/registration failures to prevent enumeration
    res.status(401).send("Error: Invalid credentials or authentication failed.");
};

//----------------------------------------------------------------------
// 1. REGISTER
//----------------------------------------------------------------------
const register = async (req, res) => {
    try {
        // 🚨 SERVER DEBUG LOGGING
        console.log(`Attempting registration for email: ${req.body.emailId}`);
          
        // Validate the data (assuming this utility handles input shape and basic checks)
        validate(req.body);
        
        const { firstName, emailId, password } = req.body;

        // 🛑 Check if user already exists
        const existingUser = await User.findOne({ emailId });
        if (existingUser) {
            // 409 Conflict is the correct status for resource already existing
            return res.status(409).send("Error: User with this email already exists.");
        }

        // Hash password and assign default role 'user'
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const userData = {
            firstName,
            emailId,
            password: hashedPassword,
            role: 'user', // Explicitly set role
        };

        const user = await User.create(userData);

        // Check if JWT_KEY is defined before signing (prevents silent crash)
        if (!process.env.JWT_KEY) {
            console.error("FATAL ERROR: JWT_KEY is not defined in environment variables!");
            return res.status(500).send("Server configuration error: JWT key missing.");
        }
        
        // Create JWT
        const token = jwt.sign(
            { _id: user._id, emailId: user.emailId, role: user.role },
            process.env.JWT_KEY,
            { expiresIn: '1h' } // Use string for clarity
        );

        const reply = {
            firstName: user.firstName,
            emailId: user.emailId,
            _id: user._id,
            role: user.role,
        };

        // Set cookie (maxAge is in milliseconds)
        res.cookie('token', token, {
            maxAge: 60 * 60 * 1000, // 1 hour
            httpOnly: true, // Recommended for security
            // Setting sameSite to 'none' if secure is false can cause issues.
            // We will stick to 'strict' which is secure, but remember for deployment,
            // you might need sameSite: 'none' AND secure: true if client and server are different domains.
            sameSite: 'strict', 
            secure: process.env.NODE_ENV === 'production', 
        });

        // Corrected response message
        res.status(201).json({
            user: reply,
            message: "Registration Successful",
            token: token 
        });
    } catch (err) {
        // 🚨 CRITICAL FIX: Log the full internal error stack
        console.error("Registration failed internally:", err); 
        
        // Send a generic 400 response with the error message
        res.status(400).send(`Error: Failed to register user. ${err.message || 'Unknown server error.'}`);
    }
};

//----------------------------------------------------------------------
// 2. LOGIN
//----------------------------------------------------------------------
const login = async (req, res) => {
// ... (login function is unchanged)
    try {
        const { emailId, password } = req.body;

        if (!emailId || !password) {
            return sendAuthError(res); // Use generic error
        }

        const user = await User.findOne({ emailId });

        // Check if user exists BEFORE accessing user.password
        if (!user) {
            return sendAuthError(res); // Use generic error
        }

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return sendAuthError(res); // Use generic error
        }

        const reply = {
            firstName: user.firstName,
            emailId: user.emailId,
            _id: user._id,
            role: user.role,
        };

        // Create JWT
        const token = jwt.sign(
            { _id: user._id, emailId: user.emailId, role: user.role },
            process.env.JWT_KEY,
            { expiresIn: '1h' }
        );

        // Set cookie
        res.cookie('token', token, {
            maxAge: 60 * 60 * 1000, // 1 hour
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });

        res.status(200).json({ // Use 200 OK for a successful login
            user: reply,
            message: "Logged In Successfully",
            token: token
        });
    } catch (err) {
        // console.error(err); // Log internal errors
        // Send generic 401 response for all login-related errors
        sendAuthError(res);
    }
};

//----------------------------------------------------------------------
// 3. LOGOUT
//----------------------------------------------------------------------
const logout = async (req, res) => {
// ... (logout function is unchanged)
    try {
        const token = req.cookies.token;

        if (token) {
            const payload = jwt.decode(token);

            // Block the current token in Redis until its natural expiration time
            // Use EXAT for absolute expiration time (in seconds)
            if (redisClient) {
                await redisClient.set(`token:${token}`, 'Blocked', 'EXAT', payload.exp);
            }
        }
        
        // Clear the cookie immediately
        res.cookie("token", '', { 
            expires: new Date(Date.now()), 
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });
        
        res.send("Logged Out Successfully");

    } catch (err) {
        // Even if Redis fails or there's an error, still clear the cookie if possible.
        res.cookie("token", '', { expires: new Date(Date.now()) });
        // console.error(err);
        res.status(500).send("Internal Server Error: Logout failed on the server side.");
    }
};

//----------------------------------------------------------------------
// 4. ADMIN REGISTER
//----------------------------------------------------------------------
const adminRegister = async (req, res) => {
// ... (adminRegister function is unchanged)
    try {
        // The middleware for checking req.result.role should handle the authentication
        // and authorization (e.g., only a SuperAdmin can create an Admin)

        validate(req.body); 
        const { firstName, emailId, password } = req.body;

        // Check for existing user
        const existingUser = await User.findOne({ emailId });
        if (existingUser) {
            return res.status(409).send("Error: User with this email already exists.");
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Explicitly set role to 'admin'
        const userData = {
            firstName,
            emailId,
            password: hashedPassword,
            role: 'admin', 
        };

        const user = await User.create(userData);

        if (!process.env.JWT_KEY) {
            console.error("FATAL ERROR: JWT_KEY is not defined in environment variables!");
            return res.status(500).send("Server configuration error: JWT key missing.");
        }
        
        const token = jwt.sign(
            { _id: user._id, emailId: user.emailId, role: user.role },
            process.env.JWT_KEY,
            { expiresIn: '1h' }
        );
        
        res.cookie('token', token, { 
            maxAge: 60 * 60 * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });
        
        res.status(201).json({
            message: "Admin Registered Successfully",
            user: { firstName: user.firstName, emailId: user.emailId, role: user.role }
        });
    } catch (err) {
        console.error("Admin registration failed internally:", err);
        res.status(400).send(`Error: Failed to register admin. ${err.message || 'Unknown server error.'}`);
    }
}

//----------------------------------------------------------------------
// 5. DELETE PROFILE
//----------------------------------------------------------------------
const deleteProfile = async (req, res) => {
// ... (deleteProfile function is unchanged)
    try {
        // Assuming req.result._id is correctly set by an authentication middleware
        const userId = req.result._id; 
        
        // 1. Delete user from the User collection
        const userDeleted = await User.findByIdAndDelete(userId);

        if (!userDeleted) {
            return res.status(404).send("Error: User not found.");
        }

        // Run to delete associated submissions
        if (Submission) {
             await Submission.deleteMany({ userId });
        }
        
        // Clear the cookie for the user being deleted
        res.cookie("token", '', { 
            expires: new Date(Date.now()), 
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });

        res.status(200).send("Deleted Successfully. User and all associated submissions removed.");

    } catch (err) {
        // console.error(err);
        res.status(500).send("Internal Server Error: Failed to delete profile.");
    }
}

module.exports = { register, login, logout, adminRegister, deleteProfile };
