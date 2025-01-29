const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const path = require('path');
const userModel = require('./models/user');
const bcrypt = require('bcrypt');
const postModel = require('./models/posts');
const jwt = require('jsonwebtoken');

// Create Express app   
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// View Engine Setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static Files
app.use(express.static(path.join(__dirname, 'public')));

// JWT Secret Management
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_change_in_production';

// Authentication Middleware
const authMiddleware = (req, res, next) => {
    console.log('Cookies:', req.cookies); // Debug: Log all cookies
    const token = req.cookies.token;
    
    console.log('Token:', token); // Debug: Log the token
    
    if (!token) {
        console.warn('No token provided'); // Improved logging
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'No token provided'
        });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log('Decoded Token:', decoded); // Debug: Log decoded token
        
        // Additional token validation
        if (!decoded.userid) {
            console.warn('Invalid token payload');
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Invalid token payload'
            });
        }
        
        req.user = decoded;
        next();
    } catch (err) {
        console.error('Token Verification Error:', err.message); // More specific error logging
        
        // Detailed error handling
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Token has expired'
            });
        }
        
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Invalid token signature'
            });
        }
        
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Invalid token'
        });
    }
};

// Authentication check middleware for views
const checkAuth = (req, res, next) => {
    res.locals.isAuthenticated = !!req.cookies.token;
    next();
};

// Apply to all routes
app.use(checkAuth);

// Add validation functions
const validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
};

const validatePassword = (password) => {
    // At least 8 characters, one uppercase, one lowercase, one number
    const re = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
    return re.test(password);
};

// Landing page route
app.get('/', (req, res) => {
    console.log('==================== Landing Page Route Hit ===================='); 
    console.log('Full Request Details:', {
        method: req.method,
        url: req.url,
        headers: req.headers,
        cookies: req.cookies
    });

    // Check if token exists and is valid
    let isAuthenticated = false;
    if (req.cookies.token) {
        try {
            jwt.verify(req.cookies.token, JWT_SECRET);
            isAuthenticated = true;
        } catch (err) {
            // Token is invalid, keep isAuthenticated as false
            console.log('Invalid token on landing page');
        }
    }

    // Render landing page
    try {
        console.log('Attempting to render landing page');
        res.status(200).render('index', { 
            title: 'BlogConnect - Share Your Stories',
            isAuthenticated: isAuthenticated
        });
    } catch (error) {
        console.error('Error rendering landing page:', error);
        res.status(500).send('Internal Server Error: Unable to render landing page');
    }
});

app.get('/login', (req, res) => {
    if (req.cookies.token) {
        return res.redirect('/posts');
    }
    
    res.render('login', { 
        title: 'Login - BlogConnect',
        error: null,
        isAuthenticated: false
    });
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.render('login', {
                title: 'Login - BlogConnect',
                error: 'Email and password are required',
                isAuthenticated: false
            });
        }

        // Find user by email
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.render('login', {
                title: 'Login - BlogConnect',
                error: 'Invalid email or password',
                isAuthenticated: false
            });
        }

        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.render('login', {
                title: 'Login - BlogConnect',
                error: 'Invalid email or password',
                isAuthenticated: false
            });
        }

        // Create token
        const token = jwt.sign(
            { userid: user._id, email: user.email }, 
            JWT_SECRET, 
            { 
                expiresIn: '24h',
                algorithm: 'HS256' // Explicitly set algorithm
            }
        );

        // Set secure cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        res.redirect('/posts');
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', {
            title: 'Login - BlogConnect',
            error: 'Server error during login',
            isAuthenticated: false
        });
    }
});

// Register page route
app.get('/register', (req, res) => {
    // If user is already logged in, redirect to posts
    if (req.cookies.token) {
        return res.redirect('/posts');
    }
    
    // Render registration page
    res.render('register', { 
        title: 'Register - BlogConnect',
        error: null,
        isAuthenticated: false
    });
});

app.post('/register', async(req, res) => {
    try {
        let { username, name, email, password, confirmPassword, age } = req.body;
        
        // Validate inputs
        if (!username || !name || !email || !password || !confirmPassword) {
            return res.render('register', {
                title: 'Register - BlogConnect',
                error: 'All fields are required',
                isAuthenticated: false
            });
        }

        // Email validation
        if (!validateEmail(email)) {
            return res.render('register', {
                title: 'Register - BlogConnect',
                error: 'Invalid email format',
                isAuthenticated: false
            });
        }

        // Password validation
        if (!validatePassword(password)) {
            return res.render('register', {
                title: 'Register - BlogConnect',
                error: 'Password must be at least 8 characters, include uppercase, lowercase, and number',
                isAuthenticated: false
            });
        }

        // Password confirmation
        if (password !== confirmPassword) {
            return res.render('register', {
                title: 'Register - BlogConnect',
                error: 'Passwords do not match',
                isAuthenticated: false
            });
        }
        
        // Check if user already exists
        let existingUser = await userModel.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.render('register', {
                title: 'Register - BlogConnect',
                error: 'User with this email or username already exists',
                isAuthenticated: false
            });
        }
        
        // Generate salt and hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Create user
        let user = await userModel.create({
            username,
            name,
            email,
            password: hashedPassword,
            age
        });
        
        // Create token
        let token = jwt.sign(
            { userid: user._id, email: user.email }, 
            JWT_SECRET, 
            { 
                expiresIn: '24h',
                algorithm: 'HS256' // Explicitly set algorithm
            }
        );
        
        // Set cookie with robust options
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours in milliseconds
        });
        
        // Redirect to posts page after successful registration
        res.redirect('/posts');
    } catch (error) {
        console.error('Registration error:', error);
        res.render('register', {
            title: 'Register - BlogConnect',
            error: 'Server error during registration',
            isAuthenticated: false
        });
    }
});

app.get('/logout', (req, res) => {
    try {
        // Clear the token cookie
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });

        // Redirect to login page
        res.redirect('/login');
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).render('error', {
            message: 'Error during logout',
            title: 'Logout Error',
            isAuthenticated: false
        });
    }
});

// Post Routes
app.get('/create-post', authMiddleware, (req, res) => {
    res.render('create-post', { 
        title: 'Create a New Post',
        isAuthenticated: true
    });
});

app.post('/create-post', authMiddleware, async (req, res) => {
    try {
        const { title, content } = req.body;
        
        console.log('Create Post - User ID:', req.user.userid); // Debug log
        console.log('Create Post - Request Body:', req.body); // Debug log
        
        // Validate input
        if (!title || !content) {
            return res.status(400).render('error', { 
                message: 'Title and content are required',
                title: 'Error Creating Post',
                isAuthenticated: true
            });
        }
        
        // Create new post
        const newPost = await postModel.create({
            title,
            content,
            author: req.user.userid,
            createdAt: new Date() // Explicitly set creation time
        });
        
        console.log('Created Post:', newPost); // Debug log
        
        // Add post to user's posts array
        const updatedUser = await userModel.findByIdAndUpdate(
            req.user.userid, 
            { $push: { post: newPost._id } },
            { new: true } // Return the updated document
        );
        
        console.log('Updated User:', updatedUser); // Debug log
        
        // Redirect to posts page or render success
        res.redirect('/posts');
    } catch (error) {
        console.error('Error creating post:', error);
        res.status(500).render('error', { 
            message: 'Server error while creating post: ' + error.message,
            title: 'Error Creating Post',
            isAuthenticated: true
        });
    }
});

app.get('/posts', authMiddleware, async (req, res) => {
    try {
        console.log('User ID for posts:', req.user.userid); // Debug log
        
        // Find all posts by the authenticated user
        const posts = await postModel.find({ author: req.user.userid });
        
        console.log('Posts found:', posts); // Debug log
        
        // If no posts, log a message
        if (posts.length === 0) {
            console.log('No posts found for user:', req.user.userid);
        }
        
        res.render('posts', { 
            title: 'Your Posts', 
            posts: posts,
            isAuthenticated: req.cookies.token !== undefined
        });
    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).render('error', { 
            message: 'Server error while fetching posts',
            title: 'Error Fetching Posts',
            isAuthenticated: req.cookies.token !== undefined
        });
    }
});

app.get('/all-posts', authMiddleware, async (req, res) => {
    try {
        // Find all posts
        const posts = await postModel.find();
        
        res.render('all-posts', { 
            title: 'All Posts', 
            posts: posts,
            isAuthenticated: true
        });
    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).render('error', { 
            message: 'Server error while fetching posts',
            title: 'Error Fetching Posts',
            isAuthenticated: true
        });
    }
});

app.get('/post/:postId', authMiddleware, async (req, res) => {
    try {
        const post = await postModel.findOne({ 
            _id: req.params.postId, 
            author: req.user.userid 
        });
        
        if (!post) {
            return res.status(404).render('error', {
                message: 'Post not found',
                title: 'Post Not Found',
                isAuthenticated: true
            });
        }
        
        res.render('single-post', { 
            title: post.title, 
            post: post,
            isAuthenticated: true
        });
    } catch (error) {
        console.error('Error fetching post:', error);
        res.status(500).render('error', { 
            message: 'Server error while fetching post',
            title: 'Error Fetching Post',
            isAuthenticated: true
        });
    }
});

app.get('/edit-post/:postId', authMiddleware, async (req, res) => {
    try {
        const post = await postModel.findOne({ 
            _id: req.params.postId, 
            author: req.user.userid 
        });
        
        if (!post) {
            return res.status(404).render('error', {
                message: 'Post not found',
                title: 'Post Not Found',
                isAuthenticated: true
            });
        }
        
        res.render('edit-post', { 
            title: 'Edit Post', 
            post: post,
            isAuthenticated: true
        });
    } catch (error) {
        console.error('Error fetching post for editing:', error);
        res.status(500).render('error', { 
            message: 'Server error while fetching post for editing',
            title: 'Error Editing Post',
            isAuthenticated: true
        });
    }
});

app.post('/edit-post/:postId', authMiddleware, async (req, res) => {
    try {
        const { title, content } = req.body;
        
        const updatedPost = await postModel.findOneAndUpdate(
            { _id: req.params.postId, author: req.user.userid },
            { title, content },
            { new: true }
        );
        
        if (!updatedPost) {
            return res.status(404).render('error', {
                message: 'Post not found',
                title: 'Post Not Found',
                isAuthenticated: true
            });
        }
        
        res.redirect('/posts');
    } catch (error) {
        console.error('Error updating post:', error);
        res.status(500).render('error', { 
            message: 'Server error while updating post',
            title: 'Error Updating Post',
            isAuthenticated: true
        });
    }
});

app.post('/like-post/:postId', authMiddleware, async (req, res) => {
    try {
        const post = await postModel.findById(req.params.postId);
        
        if (!post) {
            return res.status(404).render('error', {
                message: 'Post not found',
                title: 'Post Not Found',
                isAuthenticated: true
            });
        }
        
        // Check if user has already liked the post
        const hasLiked = post.likes.includes(req.user.userid);
        
        if (hasLiked) {
            // Unlike the post
            await postModel.findByIdAndUpdate(req.params.postId, {
                $pull: { likes: req.user.userid }
            });
        } else {
            // Like the post
            await postModel.findByIdAndUpdate(req.params.postId, {
                $addToSet: { likes: req.user.userid }
            });
        }
        
        res.redirect('/posts');
    } catch (error) {
        console.error('Error liking post:', error);
        res.status(500).render('error', { 
            message: 'Server error while liking post',
            title: 'Error Liking Post',
            isAuthenticated: true
        });
    }
});

app.put('/post/:postId', authMiddleware, async (req, res) => {
    try {
        const { title, content } = req.body;
        
        const updatedPost = await postModel.findOneAndUpdate(
            { _id: req.params.postId, author: req.user.userid },
            { title, content },
            { new: true }
        );
        
        if (!updatedPost) {
            return res.status(404).send('Post not found');
        }
        
        res.json(updatedPost);
    } catch (error) {
        console.error('Error updating post:', error);
        res.status(500).send('Server error while updating post');
    }
});

app.delete('/post/:postId', authMiddleware, async (req, res) => {
    try {
        const deletedPost = await postModel.findOneAndDelete({ 
            _id: req.params.postId, 
            author: req.user.userid 
        });
        
        if (!deletedPost) {
            return res.status(404).send('Post not found');
        }
        
        // Remove post reference from user's posts array
        await userModel.findByIdAndUpdate(req.user.userid, {
            $pull: { post: req.params.postId }
        });
        
        res.send('Post deleted successfully');
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).send('Server error while deleting post');
    }
});

// Updated error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled Error:', err);
    
    // Determine the appropriate status code
    const statusCode = err.status || 500;
    
    // Provide a detailed error response
    res.status(statusCode).json({
        error: 'Server Error',
        message: err.message || 'An unexpected error occurred',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = app;