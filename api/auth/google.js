// FILENAME: /api/auth/google.js
import { OAuth2Client } from 'google-auth-library';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';
import { supabase } from '../_supabase.js';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const JWT_SECRET = process.env.JWT_SECRET;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

async function getOrCreateUser(profile) {
    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', profile.email)
        .single();
    
    if (error && error.code !== 'PGRST116') throw error;
    if (user) return user;

    // Create a new user if one doesn't exist
    const { data: newUser, error: insertError } = await supabase
        .from('users')
        .insert({ name: profile.name, email: profile.email, provider: 'google' })
        .select()
        .single();
    
    if (insertError) throw insertError;
    return newUser;
}

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    try {
        const { token: idToken } = req.body;
        const ticket = await client.verifyIdToken({
            idToken,
            audience: GOOGLE_CLIENT_ID,
        });
        const profile = ticket.getPayload();

        const user = await getOrCreateUser(profile);

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
}