// This script handles logic for both login.html and index.html

document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    const currentPage = window.location.pathname.split('/').pop();

    // --- ROUTING ---
    if (token && currentPage === 'login.html') {
        window.location.href = 'index.html';
        return;
    }

    if (!token && currentPage === 'index.html') {
        window.location.href = 'login.html';
        return;
    }

    // --- API HELPER ---
    const api = {
        baseUrl: 'https://task-manager-backend-89q1.onrender.com/api',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        async post(endpoint, body) {
            const res = await fetch(`${this.baseUrl}${endpoint}`, {
                method: 'POST',
                headers: this.headers,
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
        // Inject style to make username and password boxes full width
        const style = document.createElement('style');
        style.textContent = `
            #login-form input[type="text"],
            #login-form input[type="password"],
            #register-form input[type="text"],
            #register-form input[type="password"] {
                width: 100%;
                box-sizing: border-box;
            }
        `;
        document.head.appendChild(style);

        const loginForm = document.getElementById('login-form');
        const registerForm = document.getElementById('register-form');
        const showRegisterLink = document.getElementById('show-register');
        const showLoginLink = document.getElementById('show-login');
        const loginView = document.getElementById('login-view');
        const registerView = document.getElementById('register-view');

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

        const fetchTasks = async () => {
            taskList.innerHTML = '<li>Loading...</li>';
            try {
                const tasks = await api.get('/tasks');
                taskList.innerHTML = '';
                if (Array.isArray(tasks)) {
                    tasks.forEach(task => {
                        const li = document.createElement('li');
                        li.className = `task-item ${task.completed ? 'completed' : ''}`;
                        li.dataset.id = task._id;

                        li.innerHTML = `
                            <span class="task-text">${task.text}</span>
                            <progress value="${task.currentCount}" max="${task.totalCount}"></progress>
                            <div class="task-actions">
                                <button class="btn btn-primary increase-btn" title="Increase">+</button>
                                <button class="btn btn-danger delete-btn" title="Delete">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                                </button>
                            </div>
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

        taskForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const text = document.getElementById('task-text').value.trim();
            const totalCount = document.getElementById('task-count').value;
            if (text && totalCount) {
                const newTask = await api.post('/tasks', { text, totalCount });
                if (newTask._id) {
                    document.getElementById('task-text').value = '';
                    document.getElementById('task-count').value = '';
                    fetchTasks();
                } else {
                    showMessage('task-message', newTask.message, 'error');
                }
            } else {
                showMessage('task-message', 'Task text and count are required.', 'error');
            }
        });

        taskList.addEventListener('click', async (e) => {
            const target = e.target;
            const li = target.closest('.task-item');
            if (!li) return;
            const id = li.dataset.id;

            if (target.classList.contains('delete-btn')) {
                const result = await api.delete(`/tasks/${id}`);
                if (result.message.includes('successfully')) {
                    li.remove();
                } else {
                    showMessage('task-message', result.message, 'error');
                }
            } else if (target.classList.contains('increase-btn') && !li.classList.contains('completed')) {
                const updatedTask = await api.put(`/tasks/${id}/increment`, {});
                if (updatedTask._id) {
                    fetchTasks();
                } else {
                    showMessage('task-message', updatedTask.message, 'error');
                }
            }
        });

        logoutBtn.addEventListener('click', () => {
            localStorage.removeItem('token');
            window.location.href = 'login.html';
        });

        fetchTasks();
    }
});