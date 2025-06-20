// FILENAME: api/auth/google.js
import { OAuth2Client } from 'google-auth-library';
import { db } from '../_db.js';
import { issueToken, setAuthCookie } from '../_utils.js';

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    try {
        const { token } = req.body;
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const { name, email, sub: googleId } = payload;

        let user = db.users.findOne(u => u.email === email);

        if (!user) {
            user = db.users.create({
                name,
                email,
                provider: 'google',
                providerId: googleId
            });
        } else if (user.provider !== 'google') {
            return res.status(409).json({ message: 'This email is already registered with a different method.' });
        }
        
        const jwtToken = issueToken(user);
        setAuthCookie(res, jwtToken);

        res.status(200).json({ success: true });

    } catch (error) {
        console.error('Google Auth Error:', error);
        res.status(500).json({ message: 'Internal server error during Google authentication.' });
    }
}