// This script handles logic for both login.html and index.html

document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    const currentPage = window.location.pathname.split('/').pop();

    // --- ROUTING ---
    // If user is on login page but has a token, redirect to main app
    if (token && currentPage === 'login.html') {
        window.location.href = 'index.html';
        return;
    }

    // If user is on main app page but has NO token, redirect to login
    if (!token && currentPage === 'index.html') {
        window.location.href = 'login.html';
        return;
    }

    // --- API HELPER ---
    const api = {
        baseUrl: 'http://localhost:3000/api',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        async post(endpoint, body) {
            const res = await fetch(`${this.baseUrl}${endpoint}`, {
                method: 'POST',
                headers: this.headers, // Updated to include Authorization header
                body: JSON.stringify(body)
            });
            return res.json();
        },
        async get(endpoint) {
            const res = await fetch(`${this.baseUrl}${endpoint}`, { headers: this.headers });
            return res.json();
        },
        async put(endpoint, body) {
            const res = await fetch(`${this.baseUrl}${endpoint}`, {
                method: 'PUT',
                headers: this.headers,
                body: JSON.stringify(body)
            });
            return res.json();
        },
        async delete(endpoint) {
            const res = await fetch(`${this.baseUrl}${endpoint}`, {
                method: 'DELETE',
                headers: this.headers
            });
            return res.json();
        }
    };

    // --- MESSAGE HANDLING ---
    const showMessage = (elementId, text, type = 'error', duration = 3000) => {
        const messageEl = document.getElementById(elementId);
        if (messageEl) {
            messageEl.textContent = text;
            messageEl.className = `message ${type}`;
            setTimeout(() => {
                messageEl.textContent = '';
                messageEl.className = 'message';
            }, duration);
        }
    };

    // --- LOGIN/REGISTER PAGE LOGIC (login.html) ---
    if (currentPage === 'login.html') {
        const loginForm = document.getElementById('login-form');
        const registerForm = document.getElementById('register-form');
        const showRegisterLink = document.getElementById('show-register');
        const showLoginLink = document.getElementById('show-login');
        const loginView = document.getElementById('login-view');
        const registerView = document.getElementById('register-view');

        // Toggle between login and register forms
        showRegisterLink.addEventListener('click', (e) => {
            e.preventDefault();
            loginView.classList.add('hidden');
            registerView.classList.remove('hidden');
        });

        showLoginLink.addEventListener('click', (e) => {
            e.preventDefault();
            registerView.classList.add('hidden');
            loginView.classList.remove('hidden');
        });

        // Handle Registration
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('register-username').value;
            const password = document.getElementById('register-password').value;
            const data = await api.post('/auth/register', { username, password });

            if (data.message.includes('successfully')) {
                showMessage('auth-message', data.message, 'success');
                setTimeout(() => {
                    registerView.classList.add('hidden');
                    loginView.classList.remove('hidden');
                    document.getElementById('login-username').value = username;
                    document.getElementById('login-password').focus();
                }, 1500);
            } else {
                showMessage('auth-message', data.message, 'error');
            }
        });

        // Handle Login
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;
            const data = await api.post('/auth/login', { username, password });

            if (data.token) {
                localStorage.setItem('token', data.token);
                window.location.href = 'index.html';
            } else {
                showMessage('auth-message', data.message, 'error');
            }
        });
    }

    // --- MAIN APP PAGE LOGIC (index.html) ---
    if (currentPage === 'index.html') {
        const taskForm = document.getElementById('task-form');
        const taskInput = document.getElementById('task-input');
        const taskList = document.getElementById('task-list');
        const welcomeMessage = document.getElementById('welcome-message');
        const logoutBtn = document.getElementById('logout-btn');

        function decodeToken(token) {
            try {
                return JSON.parse(atob(token.split('.')[1]));
            } catch (e) {
                return null;
            }
        }

        const userData = decodeToken(token);
        if (userData && userData.username) {
            welcomeMessage.textContent = `Welcome, ${userData.username}!`;
        }

        // Fetch and display tasks
        const fetchTasks = async () => {
            taskList.innerHTML = '<li>Loading...</li>';
            try {
                const tasks = await api.get('/tasks');
                taskList.innerHTML = ''; // Clear list before rendering
                if (Array.isArray(tasks)) {
                    tasks.forEach(task => {
                        const li = document.createElement('li');
                        li.className = `task-item ${task.completed ? 'completed' : ''}`;
                        li.dataset.id = task._id;

                        li.innerHTML = `
                            <input type="checkbox" class="task-checkbox" ${task.completed ? 'checked' : ''}>
                            <span class="task-text">${task.text}</span>
                            <button class="btn btn-danger delete-btn">Delete</button>
                        `;
                        taskList.appendChild(li);
                    });
                } else if (tasks.message) {
                    showMessage('task-message', tasks.message, 'error');
                }
            } catch (err) {
                taskList.innerHTML = '<li style="color:red">Failed to load tasks. Check your connection.</li>';
                showMessage('task-message', 'Error fetching tasks: ' + (err.message || err), 'error', 5000);
            }
        };

        // Handle creating a new task
        taskForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const text = taskInput.value.trim();
            if (text) {
                const newTask = await api.post('/tasks', { text });
                if (newTask._id) {
                    taskInput.value = '';
                    fetchTasks(); // Refresh the list
                } else {
                    showMessage('task-message', newTask.message, 'error');
                }
            }
        });

        // Handle task completion and deletion using event delegation
        taskList.addEventListener('click', async (e) => {
            const target = e.target;
            const li = target.closest('.task-item');
            if (!li) return;
            const id = li.dataset.id;

            // Handle task deletion
            if (target.classList.contains('delete-btn')) {
                const result = await api.delete(`/tasks/${id}`);
                if (result.message.includes('successfully')) {
                    li.remove();
                } else {
                    showMessage('task-message', result.message, 'error');
                }
            }

            // Handle task completion toggle
            if (target.classList.contains('task-text') || target.classList.contains('task-checkbox')) {
                const isCompleted = li.classList.contains('completed');
                const updatedTask = await api.put(`/tasks/${id}`, { completed: !isCompleted });
                if (updatedTask._id) {
                    fetchTasks(); // Refresh list to show updated state
                } else {
                    showMessage('task-message', updatedTask.message, 'error');
                }
            }
        });

        // Handle logout
        logoutBtn.addEventListener('click', () => {
            localStorage.removeItem('token');
            window.location.href = 'login.html';
        });

        // Initial fetch of tasks when page loads
        fetchTasks();
    }
});