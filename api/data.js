// FILENAME: /api/_data.js

const bcrypt = require('bcryptjs');

// In a real app, this MUST be an environment variable in Vercel.
// Go to your Vercel project -> Settings -> Environment Variables.
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-that-is-at-least-32-characters-long';

// In-memory "database". This resets on every server restart.
// A real database is needed for a production app.
const users = [
    {
        id: '1',
        name: 'Admin User',
        email: 'admin@example.com',
        // Hashed password for "password123"
        passwordHash: bcrypt.hashSync('password123', 10),
        role: 'admin',
        provider: 'manual'
    },
    {
        id: '2',
        name: 'Test User',
        email: 'test@example.com',
        passwordHash: bcrypt.hashSync('password123', 10),
        role: 'user',
        provider: 'manual'
    }
];

let nextUserId = 3;

function findUserByEmail(email) {
    return users.find(user => user.email === email);
}

function createUser(userData) {
    const newUser = {
        id: String(nextUserId++),
        role: 'user',
        ...userData
    };
    users.push(newUser);
    return newUser;
}

module.exports = {
    JWT_SECRET,
    users,
    findUserByEmail,
    createUser
};