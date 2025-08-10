// server.js

// --- 1. Imports and Setup ---
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// --- 2. Middleware ---

// Allow all origins (for development only)
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- 3. MongoDB Connection ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// --- 4. Mongoose Schemas (Data Models) ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
}, { timestamps: true });

const TaskSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    totalCount: { type: Number, required: true },
    currentCount: { type: Number, default: 0 },
    completed: { type: Boolean, default: false },
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);
const Task = mongoose.model('Task', TaskSchema);

// --- 5. Authentication Middleware ---
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(400).json({ message: 'Invalid token.' });
    }
};

// --- 6. API Routes ---

// == AUTHENTICATION ROUTES ==
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already taken.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during registration.', error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const payload = { id: user._id, username: user.username };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ message: 'Logged in successfully!', token });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.', error: error.message });
    }
});

// == TASK ROUTES (Protected) ==
app.get('/api/tasks', authMiddleware, async (req, res) => {
    try {
        const tasks = await Task.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.json(tasks);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching tasks.', error: error.message });
    }
});

app.post('/api/tasks', authMiddleware, async (req, res) => {
    try {
        const { text, totalCount } = req.body;
        if (!text || !totalCount || totalCount < 1) {
            return res.status(400).json({ message: 'Task text and a positive count are required.' });
        }

        const newTask = new Task({
            userId: req.user.id,
            text: text,
            totalCount: totalCount,
            currentCount: 0,
            completed: false,
        });

        await newTask.save();
        res.status(201).json(newTask);
    } catch (error) {
        res.status(500).json({ message: 'Server error creating task.', error: error.message });
    }
});

app.put('/api/tasks/:id', authMiddleware, async (req, res) => {
    try {
        const { completed } = req.body;
        const task = await Task.findById(req.params.id);

        if (!task) {
            return res.status(404).json({ message: 'Task not found.' });
        }

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

app.put('/api/tasks/:id/increment', authMiddleware, async (req, res) => {
    try {
        const task = await Task.findById(req.params.id);

        if (!task) {
            return res.status(404).json({ message: 'Task not found.' });
        }

        if (task.userId.toString() !== req.user.id) {
            return res.status(403).json({ message: 'User not authorized to update this task.' });
        }

        if (task.currentCount < task.totalCount) {
            task.currentCount += 1;
            if (task.currentCount === task.totalCount) {
                task.completed = true;
            }
            await task.save();
            res.json(task);
        } else {
            res.status(400).json({ message: 'Task is already completed.' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server error updating task.', error: error.message });
    }
});

app.delete('/api/tasks/:id', authMiddleware, async (req, res) => {
    try {
        const task = await Task.findById(req.params.id);

        if (!task) {
            return res.status(404).json({ message: 'Task not found.' });
        }

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
app.get(/^\/(?!api).*/, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- 8. Start Server ---
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
