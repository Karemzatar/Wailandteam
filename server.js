const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const PORT = process.env.PORT || 5000;

// =============================
// Basic Middleware
// =============================
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: 'wailand-security-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/css', express.static(path.join(__dirname, 'css')));
app.use('/js', express.static(path.join(__dirname, 'js')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// =============================
// Storage Files
// =============================
const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const ADMINS_FILE = path.join(__dirname, 'data', 'admins.json');
const TOKENS_FILE = path.join(__dirname, 'data', 'tokens.json');
const USER_DATA_FILE = path.join(__dirname, 'data', 'user-data.json');
const TICKETS_FILE = path.join(__dirname, 'data', 'tickets.json');
const POINTS_FILE = path.join(__dirname, 'data', 'points.json');

// Create data directory if it doesn't exist
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// Create public directory for HTML files
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir, { recursive: true });

// Create uploads directory
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// Create tickets-log directory
const ticketsLogDir = path.join(__dirname, 'tickets-log');
if (!fs.existsSync(ticketsLogDir)) fs.mkdirSync(ticketsLogDir, { recursive: true });

// =============================
// JSON Read/Write Functions
// =============================
function readJSON(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading file:', filePath, error);
    return null;
  }
}

function writeJSON(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error('Error writing file:', filePath, error);
    return false;
  }
}

// =============================
// Initialize Files on Startup
// =============================
function initializeFiles() {
  if (!fs.existsSync(USERS_FILE)) writeJSON(USERS_FILE, []);
  if (!fs.existsSync(ADMINS_FILE)) {
    const hashedPassword = bcrypt.hashSync('admin123', 12);
    writeJSON(ADMINS_FILE, [{
      id: crypto.randomUUID(),
      email: 'admin@wailand.com',
      password: hashedPassword,
      name: 'System Administrator',
      role: 'admin',
      avatar: 'A',
      createdAt: new Date().toISOString()
    }]);
  }
  if (!fs.existsSync(TOKENS_FILE)) writeJSON(TOKENS_FILE, {});
  if (!fs.existsSync(USER_DATA_FILE)) writeJSON(USER_DATA_FILE, {});
  if (!fs.existsSync(TICKETS_FILE)) writeJSON(TICKETS_FILE, []);
  if (!fs.existsSync(POINTS_FILE)) writeJSON(POINTS_FILE, {});
}

// =============================
// Create Default User Data
// =============================
function createDefaultUserData(userId) {
  return {
    userId: userId,
    dashboard: {
      totalScans: Math.floor(Math.random() * 150) + 50,
      threatsBlocked: Math.floor(Math.random() * 30) + 10,
      systemHealth: Math.floor(Math.random() * 15) + 85,
      activeTools: Math.floor(Math.random() * 5) + 3,
      securityScore: Math.floor(Math.random() * 15) + 80,
      uptime: 95 + Math.random() * 4,
      responseTime: (Math.random() * 100 + 30).toFixed(2),
      dataProcessed: Math.floor(Math.random() * 1500) + 500,
      vulnerabilities: Math.floor(Math.random() * 5)
    },
    tools: [
      { id: 1, name: 'Vulnerability Scanner', description: 'Scan your systems for security vulnerabilities and potential threats.', status: 'online', icon: 'fas fa-search', usage: Math.floor(Math.random() * 30) + 70 },
      { id: 2, name: 'Password Auditor', description: 'Check the strength of your passwords and get recommendations.', status: 'online', icon: 'fas fa-lock', usage: Math.floor(Math.random() * 30) + 60 },
      { id: 3, name: 'Firewall Manager', description: 'Configure and monitor your firewall settings in real time.', status: 'online', icon: 'fas fa-shield-alt', usage: Math.floor(Math.random() * 20) + 75 },
      { id: 4, name: 'Network Monitor', description: 'Monitor network traffic and detect suspicious activities.', status: Math.random() > 0.7 ? 'warning' : 'online', icon: 'fas fa-network-wired', usage: Math.floor(Math.random() * 40) + 40 }
    ],
    notifications: [
      { id: 1, title: 'System security scan completed successfully', message: 'The latest security scan detected no critical threats in your system.', type: 'success', timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(), read: false },
      { id: 2, title: 'Welcome to Wailand Security System', message: 'Your account has been successfully activated.', type: 'info', timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), read: true }
    ],
    profile: { 
      scans: Math.floor(Math.random() * 200) + 50, 
      tools: Math.floor(Math.random() * 6) + 2, 
      daysActive: Math.floor(Math.random() * 100) + 30 
    }
  };
}

// =============================
// Authentication Middleware
// =============================
function requireAuth(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/');
  }
}

function requireAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Admin access required' });
  }
}

// =============================
// Ticket System Functions
// =============================
const readTickets = () => {
  try {
    if (!fs.existsSync(TICKETS_FILE)) return [];
    const data = fs.readFileSync(TICKETS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading tickets:', error);
    return [];
  }
};

const writeTickets = (tickets) => {
  try {
    fs.writeFileSync(TICKETS_FILE, JSON.stringify(tickets, null, 2));
    return true;
  } catch (error) {
    console.error('Error writing tickets:', error);
    return false;
  }
};

const readPoints = () => {
  try {
    if (!fs.existsSync(POINTS_FILE)) return {};
    const data = fs.readFileSync(POINTS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading points:', error);
    return {};
  }
};

const writePoints = (points) => {
  try {
    fs.writeFileSync(POINTS_FILE, JSON.stringify(points, null, 2));
    return true;
  } catch (error) {
    console.error('Error writing points:', error);
    return false;
  }
};

// =============================
// File Upload Configuration
// =============================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${file.originalname}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024
  }
});

// =============================
// 🔐 API: User Login
// =============================
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ 
      success: false, 
      message: 'Email and password are required' 
    });
  }

  try {
    const users = readJSON(USERS_FILE) || [];
    let user = users.find(u => u.email === email);

    if (user) {
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid email or password' 
        });
      }
    } else {
      const admins = readJSON(ADMINS_FILE) || [];
      const admin = admins.find(a => a.email === email);

      if (admin) {
        const isValid = await bcrypt.compare(password, admin.password);
        if (!isValid) {
          return res.status(401).json({ 
            success: false, 
            message: 'Invalid email or password' 
          });
        }
        user = admin;
      } else {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid email or password' 
        });
      }
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      avatar: user.avatar || user.name.charAt(0).toUpperCase()
    };

    res.json({
      success: true,
      message: 'Login successful',
      user: req.session.user,
      redirectTo: user.role === 'admin' ? '/dashboard' : '/home'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during login' 
    });
  }
});

// =============================
// 📝 API: Create New Account
// =============================
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ 
      success: false, 
      message: 'All fields are required' 
    });
  }

  if (password.length < 8) {
    return res.status(400).json({ 
      success: false, 
      message: 'Password must be at least 8 characters long' 
    });
  }

  try {
    const users = readJSON(USERS_FILE) || [];
    const admins = readJSON(ADMINS_FILE) || [];

    if (users.find(u => u.email === email) || admins.find(a => a.email === email)) {
      return res.status(409).json({ 
        success: false, 
        message: 'Email already exists' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = { 
      id: crypto.randomUUID(), 
      name, 
      email, 
      password: hashedPassword, 
      role: 'user', 
      avatar: name.charAt(0).toUpperCase(),
      createdAt: new Date().toISOString(), 
      updatedAt: new Date().toISOString() 
    };

    users.push(newUser);
    writeJSON(USERS_FILE, users);

    const userData = readJSON(USER_DATA_FILE) || {};
    userData[newUser.id] = createDefaultUserData(newUser.id);
    writeJSON(USER_DATA_FILE, userData);

    res.status(201).json({ 
      success: true,
      message: 'Account created successfully', 
      user: { 
        id: newUser.id, 
        name: newUser.name, 
        email: newUser.email, 
        role: 'user' 
      } 
    });

  } catch (error) {
    console.error('Account creation error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during account creation' 
    });
  }
});

// =============================
// 👤 API: Get Current User
// =============================
app.get('/api/user', (req, res) => {
  if (req.session.user) {
    res.json({ 
      success: true, 
      user: req.session.user 
    });
  } else {
    res.status(401).json({ 
      success: false, 
      message: 'Not authenticated' 
    });
  }
});

// =============================
// 🚪 API: Logout
// =============================
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ 
        success: false, 
      message: 'Logout failed' 
      });
    }
    res.json({ 
      success: true, 
      message: 'Logout successful' 
    });
  });
});

// =============================
// 📊 API: Get Dashboard Data
// =============================
app.get('/api/dashboard', requireAuth, (req, res) => {
  const userData = readJSON(USER_DATA_FILE) || {};
  const data = userData[req.session.user.id];

  if (data && data.dashboard) {
    res.json({ 
      success: true, 
      data: data.dashboard 
    });
  } else {
    res.json({ 
      success: true, 
      data: createDefaultUserData(req.session.user.id).dashboard 
    });
  }
});

// =============================
// 🛠 API: Get Tools
// =============================
app.get('/api/tools', requireAuth, (req, res) => {
  const userData = readJSON(USER_DATA_FILE) || {};
  const data = userData[req.session.user.id];

  if (data && data.tools) {
    res.json({ 
      success: true, 
      data: data.tools 
    });
  } else {
    res.json({ 
      success: true, 
      data: createDefaultUserData(req.session.user.id).tools 
    });
  }
});

// =============================
// 🔔 API: Get Notifications
// =============================
app.get('/api/notifications', requireAuth, (req, res) => {
  const userData = readJSON(USER_DATA_FILE) || {};
  const data = userData[req.session.user.id];

  if (data && data.notifications) {
    res.json({ 
      success: true, 
      data: data.notifications 
    });
  } else {
    res.json({ 
      success: true, 
      data: createDefaultUserData(req.session.user.id).notifications 
    });
  }
});

// =============================
// 👥 API: Get Users (Admin Only)
// =============================
app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  const users = readJSON(USERS_FILE) || [];
  const usersWithoutPasswords = users.map(user => {
    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword;
  });
  res.json({ 
    success: true, 
    data: usersWithoutPasswords 
  });
});

// =============================
// ➕ API: Add User (Admin Only)
// =============================
app.post('/api/users', requireAuth, requireAdmin, (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ 
      success: false, 
      message: 'Name, email and password are required' 
    });
  }

  if (password.length < 8) {
    return res.status(400).json({ 
      success: false, 
      message: 'Password must be at least 8 characters long' 
    });
  }

  try {
    const users = readJSON(USERS_FILE) || [];
    const admins = readJSON(ADMINS_FILE) || [];

    if (users.find(u => u.email === email) || admins.find(a => a.email === email)) {
      return res.status(409).json({ 
        success: false, 
        message: 'Email already exists' 
      });
    }

    const hashedPassword = bcrypt.hashSync(password, 12);
    const newUser = { 
      id: crypto.randomUUID(), 
      name, 
      email, 
      password: hashedPassword, 
      role: role || 'user', 
      avatar: name.charAt(0).toUpperCase(),
      createdAt: new Date().toISOString(), 
      updatedAt: new Date().toISOString() 
    };

    users.push(newUser);
    writeJSON(USERS_FILE, users);

    const userData = readJSON(USER_DATA_FILE) || {};
    userData[newUser.id] = createDefaultUserData(newUser.id);
    writeJSON(USER_DATA_FILE, userData);

    const { password: _, ...userWithoutPassword } = newUser;

    res.status(201).json({ 
      success: true,
      message: 'User created successfully', 
      user: userWithoutPassword
    });

  } catch (error) {
    console.error('User creation error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during user creation' 
    });
  }
});

// =============================
// ✏️ API: Update User (Admin Only)
// =============================
app.put('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, email, role } = req.body;

  if (!name || !email) {
    return res.status(400).json({ 
      success: false, 
      message: 'Name and email are required' 
    });
  }

  try {
    let users = readJSON(USERS_FILE) || [];
    const userIndex = users.findIndex(u => u.id === id);

    if (userIndex === -1) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    const emailExists = users.find((u, index) => u.email === email && index !== userIndex);
    if (emailExists) {
      return res.status(409).json({ 
        success: false, 
        message: 'Email already exists' 
      });
    }

    users[userIndex].name = name;
    users[userIndex].email = email;
    users[userIndex].role = role || 'user';
    users[userIndex].avatar = name.charAt(0).toUpperCase();
    users[userIndex].updatedAt = new Date().toISOString();

    writeJSON(USERS_FILE, users);

    const { password: _, ...userWithoutPassword } = users[userIndex];

    res.json({ 
      success: true,
      message: 'User updated successfully', 
      user: userWithoutPassword
    });

  } catch (error) {
    console.error('User update error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during user update' 
    });
  }
});

// =============================
// 🗑 API: Delete User (Admin Only)
// =============================
app.delete('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const { id } = req.params;

  if (id === req.session.user.id) {
    return res.status(400).json({ 
      success: false, 
      message: 'Cannot delete your own account' 
    });
  }

  let users = readJSON(USERS_FILE) || [];
  const userExists = users.find(u => u.id === id);

  if (!userExists) {
    return res.status(404).json({ 
      success: false, 
      message: 'User not found' 
    });
  }

  users = users.filter(u => u.id !== id);
  writeJSON(USERS_FILE, users);

  const userData = readJSON(USER_DATA_FILE) || {};
  delete userData[id];
  writeJSON(USER_DATA_FILE, userData);

  res.json({ 
    success: true, 
    message: 'User deleted successfully' 
  });
});

// =============================
// 📈 API: Get Analytics Data
// =============================
app.get('/api/analytics', requireAuth, (req, res) => {
  const analyticsData = {
    threatAnalysis: {
      labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
      datasets: [
        {
          label: 'Threats Detected',
          data: [12, 19, 8, 15, 12, 17, 10, 14, 16, 12, 18, 14],
          borderColor: '#7a82ff',
          backgroundColor: 'rgba(122, 130, 255, 0.1)'
        },
        {
          label: 'Threats Blocked',
          data: [10, 16, 7, 13, 11, 15, 9, 12, 14, 11, 16, 13],
          borderColor: '#2ed573',
          backgroundColor: 'rgba(46, 213, 115, 0.1)'
        }
      ]
    },
    securityDistribution: {
      labels: ['Secure', 'Warning', 'Critical', 'Unknown'],
      datasets: [{
        data: [65, 20, 10, 5],
        backgroundColor: ['#2ed573', '#ffa502', '#ff4757', '#7a7aaa']
      }]
    }
  };

  res.json({
    success: true,
    data: analyticsData
  });
});

// =============================
// 👤 API: Update User Profile
// =============================
app.put('/api/profile', requireAuth, async (req, res) => {
  const { firstName, lastName, email, phone, bio, currentPassword, newPassword } = req.body;

  try {
    let users = readJSON(USERS_FILE) || [];
    let admins = readJSON(ADMINS_FILE) || [];

    let user = users.find(u => u.id === req.session.user.id);
    let isAdmin = false;

    if (!user) {
      user = admins.find(a => a.id === req.session.user.id);
      isAdmin = true;
    }

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    if (firstName && lastName) {
      user.name = `${firstName} ${lastName}`;
      user.avatar = firstName.charAt(0).toUpperCase();
    }
    if (email) user.email = email;
    user.updatedAt = new Date().toISOString();

    if (currentPassword && newPassword) {
      if (newPassword.length < 8) {
        return res.status(400).json({ 
          success: false, 
          message: 'New password must be at least 8 characters long' 
        });
      }

      const isValid = await bcrypt.compare(currentPassword, user.password);
      if (!isValid) {
        return res.status(400).json({ 
          success: false, 
          message: 'Current password is incorrect' 
        });
      }

      user.password = await bcrypt.hash(newPassword, 12);
    }

    if (isAdmin) {
      writeJSON(ADMINS_FILE, admins);
    } else {
      writeJSON(USERS_FILE, users);
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      avatar: user.avatar
    };

    res.json({ 
      success: true, 
      message: 'Profile updated successfully',
      user: req.session.user
    });

  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during profile update' 
    });
  }
});

// =============================
// ✉️ Password Reset with Nodemailer
// =============================
const transporter = nodemailer.createTransport({
  host: "smtp.office365.com",
  port: 587,
  secure: false,
  auth: {
    user: "wailand.team@outlook.com",
    pass: "Immomo24"
  }
});

// Request password reset
app.post('/api/request-reset', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ 
      success: false, 
      message: 'Email is required' 
    });
  }

  const users = readJSON(USERS_FILE) || [];
  const admins = readJSON(ADMINS_FILE) || [];
  const user = users.find(u => u.email === email) || admins.find(a => a.email === email);

  if (!user) {
    return res.status(404).json({ 
      success: false, 
      message: 'Email not found' 
    });
  }

  const resetCode = Math.floor(100000 + Math.random() * 900000);
  const tokens = readJSON(TOKENS_FILE) || {};
  tokens[email] = { 
    code: resetCode, 
    expiresAt: Date.now() + 10 * 60 * 1000
  };
  writeJSON(TOKENS_FILE, tokens);

  transporter.sendMail({
    from: 'wailand.team@outlook.com',
    to: email,
    subject: 'Password Reset Code - Wailand Security',
    text: `Your password reset code is: ${resetCode}\nThis code will expire in 10 minutes.`
  }, (err) => {
    if (err) {
      console.error('Email sending error:', err);
      return res.status(500).json({ 
        success: false, 
        message: 'Failed to send reset code' 
      });
    }

    res.json({ 
      success: true, 
      message: 'Reset code sent to your email' 
    });
  });
});

// Verify reset code
app.post('/api/verify-reset', (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ 
      success: false, 
      message: 'Email and code are required' 
    });
  }

  const tokens = readJSON(TOKENS_FILE) || {};
  const record = tokens[email];

  if (!record) {
    return res.status(400).json({ 
      success: false, 
      message: 'No valid reset code found' 
    });
  }

  if (record.expiresAt < Date.now()) {
    return res.status(400).json({ 
      success: false, 
      message: 'Reset code has expired' 
    });
  }

  if (record.code != code) {
    return res.status(400).json({ 
      success: false, 
      message: 'Invalid reset code' 
    });
  }

  res.json({ 
    success: true, 
    message: 'Code verified successfully' 
  });
});

// Reset password
app.post('/api/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).json({ 
      success: false, 
      message: 'Email and new password are required' 
    });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ 
      success: false, 
      message: 'Password must be at least 8 characters long' 
    });
  }

  try {
    let users = readJSON(USERS_FILE) || [];
    let admins = readJSON(ADMINS_FILE) || [];
    let user = users.find(u => u.email === email);
    let isAdmin = false;

    if (!user) {
      user = admins.find(a => a.email === email);
      isAdmin = true;
    }

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    user.updatedAt = new Date().toISOString();

    if (isAdmin) {
      writeJSON(ADMINS_FILE, admins);
    } else {
      writeJSON(USERS_FILE, users);
    }

    const tokens = readJSON(TOKENS_FILE) || {};
    delete tokens[email];
    writeJSON(TOKENS_FILE, tokens);

    res.json({ 
      success: true, 
      message: 'Password reset successfully' 
    });

  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during password reset' 
    });
  }
});

// =============================
// 🛠 API: Run Security Tool
// =============================
app.post('/api/tools/run/:toolId', requireAuth, (req, res) => {
  const { toolId } = req.params;

  setTimeout(() => {
    const success = Math.random() > 0.1;

    if (success) {
      res.json({
        success: true,
        message: `Tool ${toolId} executed successfully`,
        data: {
          scanResults: {
            threatsFound: Math.floor(Math.random() * 5),
            vulnerabilities: Math.floor(Math.random() * 3),
            scanTime: (Math.random() * 30 + 10).toFixed(2)
          }
        }
      });
    } else {
      res.status(500).json({
        success: false,
        message: `Tool ${toolId} execution failed`
      });
    }
  }, 2000);
});

// =============================
// Ticket System APIs
// =============================
app.get('/api/tickets', async (req, res) => {
  try {
    const tickets = readTickets();
    res.json(tickets);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/tickets/:id', async (req, res) => {
  try {
    const tickets = readTickets();
    const ticket = tickets.find(t => t.id === req.params.id);

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    res.json(ticket);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/tickets', async (req, res) => {
  try {
    const { username, email, number, type, subject } = req.body;
    const tickets = readTickets();

    const newTicket = {
      id: uuidv4(),
      username,
      email,
      number: number || '',
      type,
      subject,
      status: 'open',
      createdAt: new Date().toISOString(),
      claimedBy: null,
      messages: []
    };

    tickets.push(newTicket);
    writeTickets(tickets);

    res.json({ success: true, ticketId: newTicket.id });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/tickets/:id/claim', async (req, res) => {
  try {
    const { adminName } = req.body;
    const tickets = readTickets();
    const ticketIndex = tickets.findIndex(t => t.id === req.params.id);

    if (ticketIndex === -1) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    const points = readPoints();
    points[adminName] = (points[adminName] || 0) + 1;
    writePoints(points);

    tickets[ticketIndex].claimedBy = adminName;
    tickets[ticketIndex].status = 'claimed';
    writeTickets(tickets);

    res.json({ success: true, ticket: tickets[ticketIndex] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/tickets/:id/message', upload.single('file'), async (req, res) => {
  try {
    const { message, sender, type = 'text' } = req.body;
    const tickets = readTickets();
    const ticketIndex = tickets.findIndex(t => t.id === req.params.id);

    if (ticketIndex === -1) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    const newMessage = {
      id: uuidv4(),
      sender,
      type,
      content: message,
      timestamp: new Date().toISOString()
    };

    if (req.file) {
      newMessage.file = {
        filename: req.file.filename,
        originalname: req.file.originalname,
        path: `/uploads/${req.file.filename}`
      };
    }

    tickets[ticketIndex].messages.push(newMessage);
    writeTickets(tickets);

    io.to(req.params.id).emit('newMessage', newMessage);

    res.json({ success: true, message: newMessage });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/tickets/:id/close', async (req, res) => {
  try {
    const { reason, adminName } = req.body;
    const tickets = readTickets();
    const ticketIndex = tickets.findIndex(t => t.id === req.params.id);

    if (ticketIndex === -1) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    tickets[ticketIndex].status = 'closed';
    tickets[ticketIndex].closedReason = reason;
    tickets[ticketIndex].closedBy = adminName;
    tickets[ticketIndex].closedAt = new Date().toISOString();

    writeTickets(tickets);

    const ticket = tickets[ticketIndex];
    const logContent = `# ${ticket.subject}
Ticket Number: ${ticket.id}
From: ${ticket.username}
Email: ${ticket.email}
Phone: ${ticket.number}
Type: ${ticket.type}
Created: ${ticket.createdAt}
Status: ${ticket.status}
Claimed By: ${ticket.claimedBy || 'N/A'}
Closed By: ${ticket.closedBy || 'N/A'}
Closed Reason: ${ticket.closedReason || 'N/A'}
Closed At: ${ticket.closedAt || 'N/A'}

Messages:
${ticket.messages.map(msg => {
  const timestamp = new Date(msg.timestamp).toLocaleString();
  let content = msg.content;
  if (msg.file) {
    content = `[FILE] ${msg.file.originalname}`;
  }
  return `  [${timestamp}] ${msg.sender}: ${content}`;
}).join('\n')}
`;

    fs.writeFileSync(`tickets-log/${ticket.id}.txt`, logContent);

    io.to(req.params.id).emit('ticketClosed', {
      reason,
      adminName,
      countdown: 5
    });

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================
// 📧 API: Send Notification (Admin Only)
// =============================
app.post('/api/notifications/send', requireAuth, requireAdmin, (req, res) => {
  const { title, message, type } = req.body;

  if (!title || !message) {
    return res.status(400).json({ 
      success: false, 
      message: 'Title and message are required' 
    });
  }

  try {
    const userData = readJSON(USER_DATA_FILE) || {};

    Object.keys(userData).forEach(userId => {
      if (userData[userId] && userData[userId].notifications) {
        const newNotification = {
          id: Date.now() + Math.floor(Math.random() * 1000),
          title,
          message,
          type: type || 'info',
          timestamp: new Date().toISOString(),
          read: false
        };
        userData[userId].notifications.unshift(newNotification);
      }
    });

    writeJSON(USER_DATA_FILE, userData);

    res.json({
      success: true,
      message: 'Notification sent to all users'
    });

  } catch (error) {
    console.error('Notification send error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error while sending notification' 
    });
  }
});

// =============================
// 🌐 Serve HTML Pages
// =============================
app.get('/', (req, res) => {
  if (req.session.user) {
    if (req.session.user.role === 'admin') {
      res.redirect('/dashboard');
    } else {
      res.redirect('/home');
    }
  } else {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

app.get('/home', requireAuth, (req, res) => {
  if (req.session.user.role === 'admin') {
    res.redirect('/dashboard');
  } else {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
  }
});

app.get('/dashboard', requireAuth, (req, res) => {
  if (req.session.user.role !== 'admin') {
    res.redirect('/home');
  } else {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  }
});

app.get('/ticket-:id.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ticket-template.html'));
});

app.get('/admin-tickets.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-tickets.html'));
});

app.get('/Create-Ticket.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'Create-Ticket.html'));
});

app.get('/Tickets.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'Tickets.html'));
});

// =============================
// Socket.io Events
// =============================
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('joinTicket', (ticketId) => {
    socket.join(ticketId);
    console.log(`User ${socket.id} joined ticket ${ticketId}`);
  });

  socket.on('leaveTicket', (ticketId) => {
    socket.leave(ticketId);
    console.log(`User ${socket.id} left ticket ${ticketId}`);
  });

  socket.on('join-user', (userId) => {
    socket.join(`user-${userId}`);
    console.log(`User ${userId} joined their room`);
  });

  socket.on('join-admin', (adminId) => {
    socket.join('admin-room');
    console.log(`Admin ${adminId} joined admin room`);
  });

  socket.on('send-notification', (data) => {
    io.to(`user-${data.userId}`).emit('new-notification', data);
    console.log(`Notification sent to user ${data.userId}`);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// =============================
// Start Server
// =============================
initializeFiles();

server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 System monitoring active`);
  console.log(`🎫 Ticket system ready`);
  console.log(`🔐 Authentication system active`);
});