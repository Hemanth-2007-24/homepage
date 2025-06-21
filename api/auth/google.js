// FILENAME: /api/auth/google.js

const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const { findUserByEmail, createUser, JWT_SECRET } = require('../_data');

// Put your Google Client ID in Vercel Environment Variables
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '772260889913-3vlll8sbp620c05sg9rfhbmmuh1b8na8.apps.googleusercontent.com';
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

module.exports = async (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    try {
        const { token: idToken } = req.body;
        const ticket = await client.verifyIdToken({
            idToken,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const { name, email } = payload;

        let user = findUserByEmail(email);
        if (!user) {
            user = createUser({ name, email, provider: 'google' });
        }

        const authToken = jwt.sign({ userId: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1d' });

        res.setHeader('Set-Cookie', cookie.serialize('authToken', authToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV !== 'development',
            maxAge: 60 * 60 * 24,
            path: '/',
            sameSite: 'Lax',
        }));

        return res.status(200).json({ message: 'Google login successful!' });

    } catch (error) {
        console.error('GOOGLE AUTH ERROR:', error);
        return res.status(500).json({ message: 'Google authentication failed.' });
    }
};