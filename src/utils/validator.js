const validator = require("validator");

const validate = (data) => {
    
    // Define the required fields
    const mandatoryField = ['firstName', 'emailId', 'password'];
    
    // Define explicit password strength rules for consistent behavior
    const passwordOptions = {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 0, // Symbols can be optional if you prefer
    };

    // 1. Check for missing mandatory fields
    const missingFields = mandatoryField.filter((k) => !Object.keys(data).includes(k));

    if (missingFields.length > 0) {
        throw new Error(`Validation Error: Required fields missing: ${missingFields.join(', ')}`);
    }

    // 2. Validate Email Format
    if (!validator.isEmail(data.emailId)) {
        throw new Error("Validation Error: Invalid email address format.");
    }
    
    // 3. Validate Password Strength
    if (!validator.isStrongPassword(data.password, passwordOptions)) {
        // Provide a descriptive error message to the user
        throw new Error("Validation Error: Password must be at least 8 characters long and include 1 uppercase letter, 1 lowercase letter, and 1 number.");
    }

    // You might also want to trim whitespace from strings like email/name:
    data.firstName = data.firstName.trim();
    data.emailId = data.emailId.trim();

    // Optionally: Check if firstName is empty after trimming
    if (data.firstName.length === 0) {
        throw new Error("Validation Error: First Name cannot be empty.");
    }
};

module.exports = validate;