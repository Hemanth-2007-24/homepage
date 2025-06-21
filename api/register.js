// FILENAME: /api/register.js
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';
import { supabase } from './_supabase.js';

const JWT_SECRET = process.env.JWT_SECRET;

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password || password.length < 6) {
            return res.status(400).json({ message: 'Invalid input. Password must be at least 6 characters.' });
        }

        // Check if user already exists
        const { data: existingUser, error: findError } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();

        if (findError && findError.code !== 'PGRST116') { // PGRST116 = 'Not a single row was returned'
            throw findError;
        }
        if (existingUser) {
            return res.status(409).json({ message: 'User with this email already exists.' });
        }

        // Hash password and create new user
        const password_hash = await bcrypt.hash(password, 10);
        const { data: newUser, error: insertError } = await supabase
            .from('users')
            .insert({ name, email, password_hash, provider: 'manual' })
            .select()
            .single();

        if (insertError) throw insertError;

        const token = jwt.sign({ userId: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role }, JWT_SECRET, { expiresIn: '1d' });

        res.setHeader('Set-Cookie', cookie.serialize('authToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV !== 'development',
            maxAge: 60 * 60 * 24,
            path: '/',
            sameSite: 'Lax',
        }));

        return res.status(201).json({ message: 'Registration successful!' });

    } catch (error) {
        console.error('REGISTRATION ERROR:', error);
        return res.status(500).json({ message: 'A server error occurred.' });
    }
}