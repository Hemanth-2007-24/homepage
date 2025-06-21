// FILENAME: /api/_supabase.js
import { createClient } from '@supabase/supabase-js';

// Read the environment variables
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;

// Create and export the Supabase client
// We use the service_role key here to bypass Row Level Security (RLS)
// in our trusted server-side functions.
export const supabase = createClient(supabaseUrl, supabaseKey);