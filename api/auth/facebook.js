// FILENAME: /api/auth/facebook.js
import axios from 'axios';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';
import { supabase } from '../_supabase.js';

const FB_APP_SECRET = process.env.FB_APP_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;

async function getOrCreateUser(profile) {
    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', profile.email)
        .single();
    
    if (error && error.code !== 'PGRST116') throw error;
    if (user) return user;

    const { data: newUser, error: insertError } = await supabase
        .from('users')
        .insert({ name: profile.name, email: profile.email, provider: 'facebook' })
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
        const { token } = req.body;
        if (!FB_APP_SECRET) {
            throw new Error('Facebook App Secret is not configured.');
        }

        const { data: profile } = await axios.get(`https://graph.facebook.com/me`, {
            params: { fields: 'id,name,email', access_token: token },
        });

        if (!profile || !profile.email) {
            return res.status(400).json({ message: 'Email permission is required from Facebook.' });
        }

        const user = await getOrCreateUser(profile);

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
}