// FILENAME: /api/auth/facebook.js

const axios = require('axios');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const { findUserByEmail, createUser, JWT_SECRET } = require('../_data');

// Add these to your Vercel Environment Variables
const FB_APP_ID = process.env.FB_APP_ID || '2084193538757104';
const FB_APP_SECRET = process.env.FB_APP_SECRET; // YOU MUST SET THIS IN VERCEL

module.exports = async (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    try {
        const { token } = req.body;
        
        if (!FB_APP_SECRET) {
            throw new Error('Facebook App Secret is not configured on the server.');
        }

        // Verify the token with Facebook
        const { data } = await axios.get(`https://graph.facebook.com/me`, {
            params: {
                fields: 'id,name,email',
                access_token: token,
            },
        });

        const { name, email } = data;
        if (!email) {
            return res.status(400).json({ message: 'Email permission is required from Facebook.' });
        }
        
        let user = findUserByEmail(email);
        if (!user) {
            user = createUser({ name, email, provider: 'facebook' });
        }

        const authToken = jwt.sign({ userId: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1d' });

        res.setHeader('Set-Cookie', cookie.serialize('authToken', authToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV !== 'development',
            maxAge: 60 * 60 * 24,
            path: '/',
            sameSite: 'Lax',
        }));

        return res.status(200).json({ message: 'Facebook login successful!' });

    } catch (error) {
        console.error('FACEBOOK AUTH ERROR:', error.response ? error.response.data : error.message);
        return res.status(500).json({ message: 'Facebook authentication failed.' });
    }
};