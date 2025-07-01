// server.js

// --- 1. Imports and Setup ---
require('dotenv').config(); // Loads environment variables from .env file
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// --- 2. Middleware ---
app.use(cors()); // Allows cross-origin requests (from our frontend)
app.use(express.json()); // Parses incoming JSON requests
app.use(express.static(path.join(__dirname, 'public'))); // Serves static files (HTML, CSS, JS) from the 'public' directory

// --- 3. MongoDB Connection ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// --- 4. Mongoose Schemas (Data Models) ---

// User Schema: Defines the structure for user documents in the database
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
}, { timestamps: true });

// Task Schema: Defines the structure for task documents
const TaskSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    completed: { type: Boolean, default: false },
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);
const Task = mongoose.model('Task', TaskSchema);

// --- 5. Authentication Middleware ---
// This function will be used to protect routes that require a user to be logged in
const authMiddleware = (req, res, next) => {
    // Get token from the 'Authorization' header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format is "Bearer TOKEN"

    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Add the decoded user payload to the request object
        next(); // Proceed to the next middleware or route handler
    } catch (error) {
        res.status(400).json({ message: 'Invalid token.' });
    }
};


// --- 6. API Routes ---

// == AUTHENTICATION ROUTES ==

// POST /api/auth/register - Register a new user
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already taken.' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create and save new user
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully!' });

    } catch (error) {
        res.status(500).json({ message: 'Server error during registration.', error: error.message });
    }
});

// POST /api/auth/login - Log in a user
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user by username
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        // Create JWT token
        const payload = { id: user._id, username: user.username };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ message: 'Logged in successfully!', token });

    } catch (error) {
        res.status(500).json({ message: 'Server error during login.', error: error.message });
    }
});


// == TASK ROUTES (Protected) ==

// GET /api/tasks - Get all tasks for the logged-in user
app.get('/api/tasks', authMiddleware, async (req, res) => {
    try {
        const tasks = await Task.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.json(tasks);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching tasks.', error: error.message });
    }
});

// POST /api/tasks - Create a new task
app.post('/api/tasks', authMiddleware, async (req, res) => {
    try {
        const { text } = req.body;
        if (!text) {
            return res.status(400).json({ message: 'Task text is required.' });
        }

        const newTask = new Task({
            userId: req.user.id,
            text: text,
        });

        await newTask.save();
        res.status(201).json(newTask);

    } catch (error) {
        res.status(500).json({ message: 'Server error creating task.', error: error.message });
    }
});

// PUT /api/tasks/:id - Update a task (e.g., mark as completed)
app.put('/api/tasks/:id', authMiddleware, async (req, res) => {
    try {
        const { completed } = req.body;
        const task = await Task.findById(req.params.id);

        if (!task) {
            return res.status(404).json({ message: 'Task not found.' });
        }

        // Ensure the user owns the task
        if (task.userId.toString() !== req.user.id) {
            return res.status(403).json({ message: 'User not authorized to update this task.' });
        }
        
        task.completed = completed;
        await task.save();
        
        res.json(task);

    } catch (error) {
        res.status(500).json({ message: 'Server error updating task.', error: error.message });
    }
});


// DELETE /api/tasks/:id - Delete a task
app.delete('/api/tasks/:id', authMiddleware, async (req, res) => {
    try {
        const task = await Task.findById(req.params.id);

        if (!task) {
            return res.status(404).json({ message: 'Task not found.' });
        }

        // Ensure the user owns the task
        if (task.userId.toString() !== req.user.id) {
            return res.status(403).json({ message: 'User not authorized to delete this task.' });
        }

        await Task.findByIdAndDelete(req.params.id);

        res.json({ message: 'Task deleted successfully.' });

    } catch (error) {
        res.status(500).json({ message: 'Server error deleting task.', error: error.message });
    }
});


// --- 7. Serve Frontend ---
// For any route not handled by the API, always send the main app page (index.html).
// The frontend will handle login/logout and routing based on localStorage.
app.get(/^\/(?!api).*/, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// --- 8. Start Server ---
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
