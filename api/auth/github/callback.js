// FILENAME: api/auth/github/callback.js
import axios from 'axios';
import { db } from '../../_db.js';
import { issueToken, setAuthCookie } from '../../_utils.js';

export default async function handler(req, res) {
    const { code } = req.query;

    if (!code) {
        return res.status(400).send('Error: GitHub did not provide a code.');
    }

    try {
        // 1. Exchange code for an access token
        const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
            client_id: process.env.GITHUB_CLIENT_ID,
            client_secret: process.env.GITHUB_CLIENT_SECRET,
            code,
        }, {
            headers: { 'Accept': 'application/json' }
        });

        const accessToken = tokenResponse.data.access_token;
        if (!accessToken) {
            throw new Error('Could not retrieve access token from GitHub.');
        }

        // 2. Use access token to get user info
        const userResponse = await axios.get('https://api.github.com/user', {
            headers: { 'Authorization': `token ${accessToken}` }
        });

        const { id: githubId, name, email: githubEmail, login } = userResponse.data;

        // GitHub may not provide a public email, so we might need a fallback.
        let email = githubEmail;
        if (!email) {
            const emailsResponse = await axios.get('https://api.github.com/user/emails', {
                 headers: { 'Authorization': `token ${accessToken}` }
            });
            const primaryEmail = emailsResponse.data.find(e => e.primary && e.verified);
            email = primaryEmail ? primaryEmail.email : null;
        }

        if (!email) {
            // Redirect with an error if no verified email is found
            return res.redirect('/index.html?error=no_email_from_github#auth');
        }

        // 3. Find or create user in our database
        let user = db.users.findOne(u => u.email === email);

        if (!user) {
            user = db.users.create({
                name: name || login,
                email,
                provider: 'github',
                providerId: githubId
            });
        } else if (user.provider !== 'github') {
            return res.redirect('/index.html?error=email_in_use#auth');
        }
        
        // 4. Issue a JWT and set it as a cookie
        const jwtToken = issueToken(user);
        setAuthCookie(res, jwtToken);

        // 5. Redirect user to their profile page
        res.writeHead(302, { Location: '/profile.html' });
        res.end();

    } catch (error) {
        console.error('GitHub Callback Error:', error.response ? error.response.data : error.message);
        res.redirect('/index.html?error=github_auth_failed#auth');
    }
}