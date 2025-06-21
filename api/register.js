// FILENAME: /api/register.js

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const { findUserByEmail, createUser, JWT_SECRET } = require('./_data');

module.exports = async (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ message: 'Name, email, and password are required.' });
        }
        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
        }

        const existingUser = findUserByEmail(email);
        if (existingUser) {
            return res.status(409).json({ message: 'User with this email already exists.' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const newUser = createUser({ name, email, passwordHash, provider: 'manual' });

        const token = jwt.sign({ userId: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role }, JWT_SECRET, { expiresIn: '1d' });

        res.setHeader('Set-Cookie', cookie.serialize('authToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV !== 'development',
            maxAge: 60 * 60 * 24, // 1 day
            path: '/',
            sameSite: 'Lax',
        }));

        return res.status(201).json({ message: 'Registration successful!' });

    } catch (error) {
        console.error('REGISTRATION ERROR:', error);
        return res.status(500).json({ message: 'A server error occurred. Please try again later.' });
    }
};