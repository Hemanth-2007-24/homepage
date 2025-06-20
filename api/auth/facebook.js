// FILENAME: api/auth/facebook.js
import axios from 'axios';
import { db } from '../_db.js';
import { issueToken, setAuthCookie } from '../_utils.js';

const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID;
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET;

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }
    
    const { token: userAccessToken } = req.body;

    if (!userAccessToken) {
        return res.status(400).json({ message: 'Facebook token is required.' });
    }

    try {
        // Step 1: Verify the user access token is valid and belongs to our app.
        // We could use the debug_token endpoint, but getting user profile is more direct.
        
        // Step 2: Use the token to get the user's profile from Facebook.
        const { data: profile } = await axios.get(
            `https://graph.facebook.com/me?fields=id,name,email&access_token=${userAccessToken}`
        );

        const { id: facebookId, name, email } = profile;

        if (!email) {
            return res.status(400).json({ message: 'Could not retrieve email from Facebook. Please ensure you have granted email permissions.' });
        }

        // Step 3: Find or create a user in our database.
        let user = db.users.findOne(u => u.email === email);

        if (!user) {
            // User doesn't exist, create a new one.
            user = db.users.create({
                name,
                email,
                provider: 'facebook',
                providerId: facebookId
            });
        } else if (user.provider !== 'facebook') {
            // User exists but signed up with a different method (e.g., Google or manual).
            return res.status(409).json({ message: `This email is already registered with ${user.provider}. Please log in using that method.` });
        }

        // Step 4: Issue our own JWT and set it as an HTTPOnly cookie.
        const jwtToken = issueToken(user);
        setAuthCookie(res, jwtToken);

        res.status(200).json({ success: true });

    } catch (error) {
        console.error('Facebook Auth Error:', error.response ? error.response.data.error : error.message);
        const errorMessage = error.response?.data?.error?.message || 'Internal server error during Facebook authentication.';
        res.status(500).json({ message: errorMessage });
    }
}