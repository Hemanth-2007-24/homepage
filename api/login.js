// FILENAME: /api/login.js

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const { findUserByEmail, JWT_SECRET } = require('./_data');

module.exports = async (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required.' });
        }

        const user = findUserByEmail(email);
        if (!user || user.provider !== 'manual') {
            return res.status(401).json({ message: 'Invalid credentials or user signed up with a different method.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const token = jwt.sign({ userId: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1d' });

        res.setHeader('Set-Cookie', cookie.serialize('authToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV !== 'development',
            maxAge: 60 * 60 * 24, // 1 day
            path: '/',
            sameSite: 'Lax',
        }));

        return res.status(200).json({ message: 'Login successful!' });

    } catch (error) {
        console.error('LOGIN ERROR:', error);
        return res.status(500).json({ message: 'A server error occurred. Please try again later.' });
    }
};