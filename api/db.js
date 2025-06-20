// FILENAME: api/_db.js
import bcrypt from 'bcryptjs';

// --- IN-MEMORY DATABASE (FOR DEMO PURPOSES) ---
// In a real app, you would connect to Vercel Postgres, MongoDB, etc.
const users = [];
let userIdCounter = 1;

// Seed the database with the admin user
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@example.com';
const existingAdmin = users.find(u => u.email === ADMIN_EMAIL);
if (!existingAdmin) {
    users.push({
        id: userIdCounter++,
        name: 'Admin User',
        email: ADMIN_EMAIL,
        // In a real scenario, you'd set a strong initial password
        passwordHash: bcrypt.hashSync('supersecretpassword', 10),
        provider: 'manual',
        role: 'admin' // Special role for the admin
    });
}


export const db = {
    users: {
        find: (callback) => users.filter(callback),
        findOne: (callback) => users.find(callback),
        create: (userData) => {
            const newUser = {
                id: userIdCounter++,
                ...userData,
                role: userData.email === ADMIN_EMAIL ? 'admin' : 'user'
            };
            users.push(newUser);
            return newUser;
        },
        getAll: () => users,
    }
};