// =============================
// Required npm Modules
// =============================
const express = require('express');
const fs = require('fs').promises;
const fsSync = require('fs');
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
const axios = require('axios');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const PORT = process.env.PORT || 3000;

// =============================
// CORS Configuration
// =============================
app.use(cors({
  origin: ["http://localhost:3000", "http://localhost:5500", "https://wailand.xyz"],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  credentials: true
}));

app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
    return res.sendStatus(204);
  }
  next();
});

// =============================
// Security Headers
// =============================
app.use((req, res, next) => {
  // CSP - Less restrictive for development
  res.setHeader(
    "Content-Security-Policy",
    "default-src * 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; " +
    "style-src * 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
    "script-src * 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; " +
    "font-src * 'self' https://cdnjs.cloudflare.com data:; " +
    "img-src * 'self' data: blob:; " +
    "connect-src * 'self' ws://localhost:* wss://localhost:*;"
  );
  
  // Other security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  
  next();
});

// =============================
// Body Parsers
// =============================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// =============================
// Session Configuration
// =============================
app.use(session({
  name: 'wailand.session',
  secret: process.env.SESSION_SECRET || 'wailand-security-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true in production with HTTPS
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax'
  },
  rolling: true
}));

// =============================
// Static Files
// =============================
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1d',
  index: false
}));

app.use('/css', express.static(path.join(__dirname, 'css')));
app.use('/js', express.static(path.join(__dirname, 'js')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  maxAge: '7d'
}));

// =============================
// File Paths Configuration
// =============================
const DATA_DIR = path.join(__dirname, 'data');
const FILES = {
  status: path.join(DATA_DIR, 'status.json'),
  users: path.join(DATA_DIR, 'users.json'),
  admins: path.join(DATA_DIR, 'admins.json'),
  tokens: path.join(DATA_DIR, 'tokens.json'),
  userData: path.join(DATA_DIR, 'user-data.json'),
  tickets: path.join(DATA_DIR, 'tickets.json'),
  points: path.join(DATA_DIR, 'points.json'),
  careers: path.join(DATA_DIR, 'careers.json'),
  applications: path.join(DATA_DIR, 'applications.json'),
  messages: path.join(DATA_DIR, 'messages.json'),
  logs: path.join(DATA_DIR, 'logs.json')
};

// =============================
// Database Configuration
// =============================
const DB_PATH = path.join(__dirname, 'wailand.db');
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('❌ Error opening database:', err.message);
    process.exit(1);
  } else {
    console.log('✅ Connected to SQLite database');
  }
});

// =============================
// Utility Functions
// =============================
const ensureDirExists = async (dirPath) => {
  try {
    await fs.access(dirPath);
  } catch {
    await fs.mkdir(dirPath, { recursive: true });
  }
};

const readJSONFile = async (filePath, defaultValue = null) => {
  try {
    await fs.access(filePath);
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (defaultValue !== null) {
      await writeJSONFile(filePath, defaultValue);
    }
    return defaultValue;
  }
};

const writeJSONFile = async (filePath, data) => {
  try {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error(`❌ Error writing to ${filePath}:`, error);
    return false;
  }
};

const logActivity = async (type, message, userId = null, details = {}) => {
  try {
    const logs = await readJSONFile(FILES.logs, []);
    const logEntry = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      type,
      message,
      userId,
      details,
      ip: details.ip || 'unknown'
    };
    
    logs.push(logEntry);
    
    // Keep only last 1000 logs
    if (logs.length > 1000) {
      logs.splice(0, logs.length - 1000);
    }
    
    await writeJSONFile(FILES.logs, logs);
    console.log(`📝 ${type.toUpperCase()}: ${message}`);
  } catch (error) {
    console.error('❌ Error logging activity:', error);
  }
};

// =============================
// Database Initialization
// =============================
const initializeDatabase = () => {
  return new Promise((resolve, reject) => {
    const queries = [
      // Users table
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        avatar TEXT DEFAULT '',
        phone TEXT,
        department TEXT,
        position TEXT,
        is_active BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME
      )`,

      // Security tools table
      `CREATE TABLE IF NOT EXISTS security_tools (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        icon TEXT DEFAULT 'fas fa-shield-alt',
        status TEXT DEFAULT 'online',
        usage_percentage INTEGER DEFAULT 0,
        enabled BOOLEAN DEFAULT 1,
        user_id INTEGER,
        last_run DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`,

      // Notifications table
      `CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT DEFAULT 'info',
        is_read BOOLEAN DEFAULT 0,
        action_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`,

      // User statistics table
      `CREATE TABLE IF NOT EXISTS user_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        total_scans INTEGER DEFAULT 0,
        threats_blocked INTEGER DEFAULT 0,
        active_tools INTEGER DEFAULT 0,
        system_health INTEGER DEFAULT 100,
        days_active INTEGER DEFAULT 1,
        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`,

      // Tickets table
      `CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT DEFAULT 'general',
        priority TEXT DEFAULT 'medium',
        status TEXT DEFAULT 'open',
        assigned_to INTEGER,
        attachment TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        closed_at DATETIME,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
      )`,

      // Ticket messages table
      `CREATE TABLE IF NOT EXISTS ticket_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        attachment TEXT,
        is_internal BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`,

      // Contact messages table
      `CREATE TABLE IF NOT EXISTS contact_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      )`,

      // Services table for uptime monitoring
      `CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        status TEXT DEFAULT 'unknown',
        response_time INTEGER DEFAULT 0,
        last_checked DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,

      // Careers table
      `CREATE TABLE IF NOT EXISTS careers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        department TEXT NOT NULL,
        type TEXT NOT NULL,
        location TEXT NOT NULL,
        employment_type TEXT NOT NULL,
        salary TEXT,
        experience TEXT,
        description TEXT NOT NULL,
        full_description TEXT,
        requirements TEXT,
        benefits TEXT,
        status TEXT DEFAULT 'active',
        posted_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        deadline DATE,
        views INTEGER DEFAULT 0
      )`,

      // Job applications table
      `CREATE TABLE IF NOT EXISTS job_applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL,
        applicant_name TEXT NOT NULL,
        applicant_email TEXT NOT NULL,
        applicant_phone TEXT,
        cover_letter TEXT,
        resume_path TEXT,
        status TEXT DEFAULT 'pending',
        applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        reviewed_at DATETIME,
        notes TEXT,
        FOREIGN KEY (job_id) REFERENCES careers(job_id) ON DELETE CASCADE
      )`,

      // Activity logs table
      `CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      )`
    ];

    const runQuery = (index) => {
      if (index >= queries.length) {
        seedInitialData().then(resolve).catch(reject);
        return;
      }

      db.run(queries[index], (err) => {
        if (err) {
          console.error(`❌ Error creating table ${index + 1}:`, err.message);
          reject(err);
        } else {
          runQuery(index + 1);
        }
      });
    };

    runQuery(0);
  });
};

const seedInitialData = async () => {
  return new Promise((resolve, reject) => {
    // Check if admin exists
    db.get('SELECT id FROM users WHERE username = ?', ['admin'], (err, row) => {
      if (err) {
        reject(err);
        return;
      }

      if (!row) {
        const hashedPassword = bcrypt.hashSync('admin123', 10);
        db.run(
          `INSERT INTO users (username, email, password, full_name, role, avatar) 
           VALUES (?, ?, ?, ?, ?, ?)`,
          ['admin', 'admin@wailand.com', hashedPassword, 'System Administrator', 'admin', 'A'],
          function(err) {
            if (err) {
              reject(err);
              return;
            }

            const adminId = this.lastID;
            
            // Create admin stats
            db.run(
              'INSERT INTO user_stats (user_id) VALUES (?)',
              [adminId],
              (err) => {
                if (err) {
                  reject(err);
                  return;
                }
                
                // Create default user
                const userHashedPassword = bcrypt.hashSync('user123', 10);
                db.run(
                  `INSERT INTO users (username, email, password, full_name, avatar) 
                   VALUES (?, ?, ?, ?, ?)`,
                  ['user', 'user@wailand.com', userHashedPassword, 'Regular User', 'U'],
                  function(err) {
                    if (err) {
                      reject(err);
                      return;
                    }
                    
                    const userId = this.lastID;
                    
                    // Create user stats
                    db.run(
                      'INSERT INTO user_stats (user_id) VALUES (?)',
                      [userId],
                      (err) => {
                        if (err) {
                          reject(err);
                          return;
                        }
                        
                        // Create default tools for user
                        const defaultTools = [
                          ['Vulnerability Scanner', 'Scan your system for security vulnerabilities', 'fas fa-search', userId],
                          ['Firewall Monitor', 'Monitor and manage firewall rules', 'fas fa-shield-alt', userId],
                          ['Network Analyzer', 'Analyze network traffic for anomalies', 'fas fa-network-wired', userId],
                          ['Malware Detector', 'Detect and remove malicious software', 'fas fa-virus', userId]
                        ];

                        const insertTool = (toolIndex) => {
                          if (toolIndex >= defaultTools.length) {
                            resolve();
                            return;
                          }

                          const tool = defaultTools[toolIndex];
                          db.run(
                            'INSERT INTO security_tools (name, description, icon, user_id) VALUES (?, ?, ?, ?)',
                            tool,
                            (err) => {
                              if (err) {
                                reject(err);
                                return;
                              }
                              insertTool(toolIndex + 1);
                            }
                          );
                        };

                        insertTool(0);
                      }
                    );
                  }
                );
              }
            );
          }
        );
      } else {
        resolve();
      }
    });
  });
};

// =============================
// Authentication Middlewares
// =============================
const JWT_SECRET = process.env.JWT_SECRET || 'wailand-secure-jwt-secret-2024-key';

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) {
        req.user = user;
        req.authMethod = 'jwt';
      }
      next();
    });
  } else {
    next();
  }
};

const requireAuth = (req, res, next) => {
  // Check session first
  if (req.session && req.session.user) {
    req.user = req.session.user;
    req.authMethod = 'session';
    return next();
  }
  
  // Check JWT
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid or expired token' 
        });
      }
      req.user = user;
      req.authMethod = 'jwt';
      next();
    });
  } else {
    return res.status(401).json({ 
      success: false, 
      message: 'Authentication required' 
    });
  }
};

const requireAdmin = (req, res, next) => {
  requireAuth(req, res, () => {
    if (req.user.role === 'admin') {
      next();
    } else {
      return res.status(403).json({ 
        success: false, 
        message: 'Admin access required' 
      });
    }
  });
};

// =============================
// File Upload Configuration
// =============================
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    await ensureDirExists(uploadDir);
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|pdf|doc|docx|txt/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (extname && mimetype) {
    cb(null, true);
  } else {
    cb(new Error('Only images, PDFs, and documents are allowed'), false);
  }
};

const upload = multer({ 
  storage, 
  fileFilter,
  limits: { 
    fileSize: 10 * 1024 * 1024 // 10MB
  }
});

// =============================
// Socket.io Events
// =============================
io.on('connection', (socket) => {
  console.log('✅ User connected:', socket.id);

  socket.on('joinTicket', (ticketId) => {
    socket.join(`ticket-${ticketId}`);
    console.log(`User ${socket.id} joined ticket ${ticketId}`);
  });

  socket.on('join-user', (userId) => {
    socket.join(`user-${userId}`);
    console.log(`User ${userId} joined their room`);
  });

  socket.on('join-admin', () => {
    socket.join('admin-room');
    console.log(`Admin joined admin room`);
  });

  socket.on('sendMessage', (data) => {
    const { ticketId, message, userId } = data;
    io.to(`ticket-${ticketId}`).emit('newMessage', {
      ...data,
      timestamp: new Date().toISOString()
    });
  });

  socket.on('updateTicket', (data) => {
    io.to(`ticket-${data.ticketId}`).emit('ticketUpdated', data);
    io.to('admin-room').emit('ticketUpdated', data);
  });

  socket.on('disconnect', () => {
    console.log('❌ User disconnected:', socket.id);
  });
});

// =============================
// Routes
// =============================

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Wailand Server is running',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Authentication Routes
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }

    db.get('SELECT * FROM users WHERE email = ? OR username = ?', 
      [email, email], 
      async (err, user) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ 
            success: false, 
            message: 'Database error' 
          });
        }

        if (!user) {
          return res.status(401).json({ 
            success: false, 
            message: 'Invalid credentials' 
          });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
          return res.status(401).json({ 
            success: false, 
            message: 'Invalid credentials' 
          });
        }

        // Update last login
        db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

        // Create session
        const userSession = {
          id: user.id,
          username: user.username,
          email: user.email,
          name: user.full_name,
          role: user.role,
          avatar: user.avatar || user.full_name.charAt(0).toUpperCase()
        };
        
        req.session.user = userSession;

        // Generate JWT token
        const token = jwt.sign(
          { 
            id: user.id, 
            username: user.username, 
            email: user.email,
            role: user.role,
            name: user.full_name 
          },
          JWT_SECRET,
          { expiresIn: '24h' }
        );

        // Log activity
        await logActivity('login', `User ${user.username} logged in`, user.id, { ip: req.ip });

        res.json({
          success: true,
          message: 'Login successful',
          token,
          user: userSession,
          redirectTo: user.role === 'admin' ? '/dashboard' : '/home'
        });
      }
    );
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during login' 
    });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, full_name } = req.body;

    if (!username || !email || !password || !full_name) {
      return res.status(400).json({ 
        success: false, 
        message: 'All fields are required' 
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid email format' 
      });
    }

    // Validate password strength
    if (password.length < 8) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 8 characters long' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(
      `INSERT INTO users (username, email, password, full_name, avatar) 
       VALUES (?, ?, ?, ?, ?)`,
      [username, email, hashedPassword, full_name, full_name.charAt(0).toUpperCase()],
      async function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ 
              success: false, 
              message: 'Username or email already exists' 
            });
          }
          console.error('Registration error:', err);
          return res.status(500).json({ 
            success: false, 
            message: 'Registration failed' 
          });
        }

        const userId = this.lastID;
        
        // Create user stats
        db.run(
          'INSERT INTO user_stats (user_id) VALUES (?)',
          [userId]
        );

        // Create default tools for user
        const defaultTools = [
          ['Vulnerability Scanner', 'Scan your system for security vulnerabilities', 'fas fa-search', userId],
          ['Firewall Monitor', 'Monitor and manage firewall rules', 'fas fa-shield-alt', userId],
          ['Network Analyzer', 'Analyze network traffic for anomalies', 'fas fa-network-wired', userId],
          ['Malware Detector', 'Detect and remove malicious software', 'fas fa-virus', userId]
        ];

        defaultTools.forEach(tool => {
          db.run(
            'INSERT INTO security_tools (name, description, icon, user_id) VALUES (?, ?, ?, ?)',
            tool
          );
        });

        // Create welcome notification
        db.run(
          'INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)',
          [userId, 'Welcome to Wailand! 🎉', 'Your account has been created successfully. Start exploring our security tools.', 'success']
        );

        // Log activity
        await logActivity('registration', `New user registered: ${username}`, userId, { ip: req.ip });

        res.json({
          success: true,
          message: 'Registration successful! You can now login.',
          userId: userId
        });
      }
    );
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during registration' 
    });
  }
});

app.post('/api/logout', (req, res) => {
  if (req.session.user) {
    const userId = req.session.user.id;
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ 
          success: false, 
          message: 'Logout failed' 
        });
      }
      
      // Log activity
      logActivity('logout', `User logged out`, userId, { ip: req.ip });
      
      res.json({ 
        success: true, 
        message: 'Logged out successfully' 
      });
    });
  } else {
    res.json({ 
      success: true, 
      message: 'Already logged out' 
    });
  }
});

// User Routes
app.get('/api/user', requireAuth, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

app.get('/api/user/profile', requireAuth, (req, res) => {
  const userId = req.user.id;
  
  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ 
        success: false, 
        message: 'Database error' 
      });
    }

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Remove sensitive data
    delete user.password;
    
    res.json({
      success: true,
      user: user
    });
  });
});

app.put('/api/user/profile', requireAuth, (req, res) => {
  const userId = req.user.id;
  const { full_name, phone, department, position } = req.body;
  
  db.run(
    `UPDATE users 
     SET full_name = ?, phone = ?, department = ?, position = ?, updated_at = CURRENT_TIMESTAMP 
     WHERE id = ?`,
    [full_name, phone, department, position, userId],
    function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Failed to update profile' 
        });
      }

      res.json({
        success: true,
        message: 'Profile updated successfully'
      });
    }
  );
});

// Dashboard Routes
app.get('/api/dashboard', requireAuth, (req, res) => {
  const userId = req.user.id;

  db.get('SELECT * FROM user_stats WHERE user_id = ?', [userId], (err, stats) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ 
        success: false, 
        message: 'Database error' 
      });
    }

    db.get('SELECT COUNT(*) as count FROM security_tools WHERE user_id = ? AND enabled = 1', 
      [userId], 
      (err, toolsCount) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ 
            success: false, 
            message: 'Database error' 
          });
        }

        // Get recent notifications count
        db.get('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0', 
          [userId], 
          (err, notificationsCount) => {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ 
                success: false, 
                message: 'Database error' 
              });
            }

            // Get recent tickets count
            db.get('SELECT COUNT(*) as count FROM tickets WHERE user_id = ? AND status = ?', 
              [userId, 'open'], 
              (err, openTicketsCount) => {
                if (err) {
                  console.error('Database error:', err);
                  return res.status(500).json({ 
                    success: false, 
                    message: 'Database error' 
                  });
                }

                const dashboardData = {
                  totalScans: stats?.total_scans || 0,
                  threatsBlocked: stats?.threats_blocked || 0,
                  systemHealth: stats?.system_health || 100,
                  activeTools: toolsCount?.count || 0,
                  daysActive: stats?.days_active || 1,
                  unreadNotifications: notificationsCount?.count || 0,
                  openTickets: openTicketsCount?.count || 0,
                  securityScore: Math.min(100, Math.floor((stats?.threats_blocked || 0) / Math.max(1, (stats?.total_scans || 1)) * 100)),
                  uptime: 95 + Math.random() * 4,
                  responseTime: (Math.random() * 100 + 30).toFixed(2),
                  dataProcessed: (stats?.total_scans || 0) * 150,
                  vulnerabilities: Math.floor(Math.random() * 5)
                };

                res.json({
                  success: true,
                  data: dashboardData
                });
              }
            );
          }
        );
      }
    );
  });
});

// Security Tools Routes
app.get('/api/tools', requireAuth, (req, res) => {
  db.all(
    `SELECT id, name, description, icon, status, usage_percentage as usage, last_run 
     FROM security_tools 
     WHERE user_id = ? AND enabled = 1 
     ORDER BY name`,
    [req.user.id],
    (err, tools) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error' 
        });
      }

      res.json({
        success: true,
        data: tools || []
      });
    }
  );
});

app.post('/api/tools/run/:id', requireAuth, (req, res) => {
  const toolId = req.params.id;
  const userId = req.user.id;

  db.get('SELECT * FROM security_tools WHERE id = ? AND user_id = ?', 
    [toolId, userId], 
    (err, tool) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error' 
        });
      }

      if (!tool) {
        return res.status(404).json({ 
          success: false, 
          message: 'Tool not found' 
        });
      }

      // Simulate tool execution with realistic results
      const newUsage = Math.min(100, tool.usage_percentage + Math.floor(Math.random() * 20) + 5);
      const isSuccessful = Math.random() > 0.1; // 90% success rate
      
      // Update tool usage and last run
      db.run(
        'UPDATE security_tools SET usage_percentage = ?, last_run = CURRENT_TIMESTAMP WHERE id = ?',
        [newUsage, toolId]
      );

      // Update user stats
      db.run(
        'UPDATE user_stats SET total_scans = total_scans + 1 WHERE user_id = ?',
        [userId]
      );

      let notificationTitle = `${tool.name} Executed`;
      let notificationMessage = `${tool.name} was executed successfully`;
      let notificationType = 'success';
      
      // Randomly detect and block threats
      const threatsDetected = Math.floor(Math.random() * 3);
      if (threatsDetected > 0) {
        db.run(
          'UPDATE user_stats SET threats_blocked = threats_blocked + ? WHERE user_id = ?',
          [threatsDetected, userId]
        );

        notificationTitle = 'Threats Blocked!';
        notificationMessage = `${tool.name} detected and blocked ${threatsDetected} potential threat(s)`;
        notificationType = 'warning';
      }

      // Create notification
      db.run(
        'INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)',
        [userId, notificationTitle, notificationMessage, notificationType]
      );

      // Log activity
      logActivity('tool_execution', `User ran tool: ${tool.name}`, userId);

      res.json({
        success: true,
        message: notificationMessage,
        newUsage: newUsage,
        threatsBlocked: threatsDetected,
        toolName: tool.name
      });
    }
  );
});

// Notifications Routes
app.get('/api/notifications', requireAuth, (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  const page = parseInt(req.query.page) || 1;
  const offset = (page - 1) * limit;
  
  db.all(
    `SELECT id, title, message, type, is_read as read, created_at as timestamp, action_url
     FROM notifications 
     WHERE user_id = ? 
     ORDER BY created_at DESC 
     LIMIT ? OFFSET ?`,
    [req.user.id, limit, offset],
    (err, notifications) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error' 
        });
      }

      // Get total count for pagination
      db.get(
        'SELECT COUNT(*) as total FROM notifications WHERE user_id = ?',
        [req.user.id],
        (err, countResult) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ 
              success: false, 
              message: 'Database error' 
            });
          }

          res.json({
            success: true,
            data: notifications || [],
            pagination: {
              page,
              limit,
              total: countResult.total,
              totalPages: Math.ceil(countResult.total / limit)
            }
          });
        }
      );
    }
  );
});

app.post('/api/notifications/:id/read', requireAuth, (req, res) => {
  const notificationId = req.params.id;
  const userId = req.user.id;

  db.run(
    'UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?',
    [notificationId, userId],
    function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error' 
        });
      }

      if (this.changes === 0) {
        return res.status(404).json({ 
          success: false, 
          message: 'Notification not found' 
        });
      }

      res.json({
        success: true,
        message: 'Notification marked as read'
      });
    }
  );
});

app.post('/api/notifications/mark-all-read', requireAuth, (req, res) => {
  db.run(
    'UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0',
    [req.user.id],
    function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error' 
        });
      }

      res.json({
        success: true,
        message: `Marked ${this.changes} notifications as read`
      });
    }
  );
});

// Ticket System Routes
app.get('/api/tickets', requireAuth, (req, res) => {
  const userId = req.user.id;
  const isAdmin = req.user.role === 'admin';
  const status = req.query.status;
  const limit = parseInt(req.query.limit) || 50;
  const page = parseInt(req.query.page) || 1;
  const offset = (page - 1) * limit;

  let query = `
    SELECT t.*, u.username as user_name, u.email as user_email, 
           a.username as assigned_name, 
           COUNT(tm.id) as message_count
    FROM tickets t
    LEFT JOIN users u ON t.user_id = u.id
    LEFT JOIN users a ON t.assigned_to = a.id
    LEFT JOIN ticket_messages tm ON t.id = tm.ticket_id
  `;

  const params = [];
  let whereClause = '';

  if (!isAdmin) {
    whereClause = 'WHERE t.user_id = ?';
    params.push(userId);
  }

  if (status) {
    whereClause += whereClause ? ' AND t.status = ?' : 'WHERE t.status = ?';
    params.push(status);
  }

  query += whereClause + ' GROUP BY t.id ORDER BY t.created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  db.all(query, params, (err, tickets) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ 
        success: false, 
        message: 'Database error' 
      });
    }

    // Get total count
    let countQuery = 'SELECT COUNT(*) as total FROM tickets t';
    const countParams = [];
    
    if (!isAdmin) {
      countQuery += ' WHERE t.user_id = ?';
      countParams.push(userId);
    }
    
    if (status && !isAdmin) {
      countQuery += ' AND t.status = ?';
      countParams.push(status);
    } else if (status && isAdmin) {
      countQuery += ' WHERE t.status = ?';
      countParams.push(status);
    }

    db.get(countQuery, countParams, (err, countResult) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error' 
        });
      }

      res.json({
        success: true,
        data: tickets || [],
        pagination: {
          page,
          limit,
          total: countResult.total,
          totalPages: Math.ceil(countResult.total / limit)
        }
      });
    });
  });
});

app.get('/api/tickets/:id', requireAuth, (req, res) => {
  const ticketId = req.params.id;
  const userId = req.user.id;
  const isAdmin = req.user.role === 'admin';

  // Get ticket details
  db.get(
    `SELECT t.*, u.username as user_name, u.email as user_email, 
            a.username as assigned_name, a.email as assigned_email
     FROM tickets t
     LEFT JOIN users u ON t.user_id = u.id
     LEFT JOIN users a ON t.assigned_to = a.id
     WHERE t.id = ? ${!isAdmin ? 'AND t.user_id = ?' : ''}`,
    !isAdmin ? [ticketId, userId] : [ticketId],
    (err, ticket) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error' 
        });
      }

      if (!ticket) {
        return res.status(404).json({ 
          success: false, 
          message: 'Ticket not found' 
        });
      }

      // Get ticket messages
      db.all(
        `SELECT tm.*, u.username, u.avatar, u.role
         FROM ticket_messages tm
         LEFT JOIN users u ON tm.user_id = u.id
         WHERE tm.ticket_id = ?
         ORDER BY tm.created_at ASC`,
        [ticketId],
        (err, messages) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ 
              success: false, 
              message: 'Database error' 
            });
          }

          res.json({
            success: true,
            ticket: ticket,
            messages: messages || []
          });
        }
      );
    }
  );
});

app.post('/api/tickets', requireAuth, upload.single('attachment'), (req, res) => {
  const userId = req.user.id;
  const { title, description, category, priority } = req.body;
  const attachment = req.file ? req.file.filename : null;

  if (!title || !description) {
    return res.status(400).json({ 
      success: false, 
      message: 'Title and description are required' 
    });
  }

  const ticketId = `TKT-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

  db.run(
    `INSERT INTO tickets (ticket_id, user_id, title, description, category, priority, attachment)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [ticketId, userId, title, description, category || 'general', priority || 'medium', attachment],
    async function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Failed to create ticket' 
        });
      }

      const newTicketId = this.lastID;

      // Create initial message
      db.run(
        'INSERT INTO ticket_messages (ticket_id, user_id, message) VALUES (?, ?, ?)',
        [newTicketId, userId, description]
      );

      // Create notification for user
      db.run(
        'INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)',
        [userId, 'Ticket Created', `Your ticket "${title}" has been created successfully`, 'success']
      );

      // Notify admins
      db.all('SELECT id FROM users WHERE role = ?', ['admin'], (err, admins) => {
        if (!err && admins) {
          admins.forEach(admin => {
            db.run(
              'INSERT INTO notifications (user_id, title, message, type, action_url) VALUES (?, ?, ?, ?, ?)',
              [admin.id, 'New Ticket Created', `New ticket: ${title}`, 'info', `/admin/tickets/${newTicketId}`]
            );
          });
        }
      });

      // Log activity
      await logActivity('ticket_created', `Created ticket: ${title}`, userId);

      // Emit socket event
      io.to('admin-room').emit('newTicket', {
        ticketId: newTicketId,
        title,
        userId,
        userName: req.user.name,
        timestamp: new Date().toISOString()
      });

      res.json({
        success: true,
        message: 'Ticket created successfully',
        ticketId: newTicketId,
        ticketNumber: ticketId
      });
    }
  );
});

app.post('/api/tickets/:id/messages', requireAuth, upload.single('attachment'), (req, res) => {
  const ticketId = req.params.id;
  const userId = req.user.id;
  const { message, isInternal } = req.body;
  const attachment = req.file ? req.file.filename : null;

  if (!message) {
    return res.status(400).json({ 
      success: false, 
      message: 'Message is required' 
    });
  }

  // Check if user has access to this ticket
  db.get(
    'SELECT * FROM tickets WHERE id = ? AND (user_id = ? OR ? = (SELECT role FROM users WHERE id = ? AND role = ?))',
    [ticketId, userId, req.user.role, userId, 'admin'],
    (err, ticket) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error' 
        });
      }

      if (!ticket) {
        return res.status(403).json({ 
          success: false, 
          message: 'Access denied to this ticket' 
        });
      }

      // Add message
      db.run(
        `INSERT INTO ticket_messages (ticket_id, user_id, message, attachment, is_internal)
         VALUES (?, ?, ?, ?, ?)`,
        [ticketId, userId, message, attachment, isInternal ? 1 : 0],
        async function(err) {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ 
              success: false, 
              message: 'Failed to send message' 
            });
          }

          // Update ticket timestamp
          db.run(
            'UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [ticketId]
          );

          // Get user info for socket
          db.get('SELECT username, avatar, role FROM users WHERE id = ?', [userId], async (err, user) => {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ 
                success: false, 
                message: 'Database error' 
              });
            }

            const messageData = {
              id: this.lastID,
              ticket_id: parseInt(ticketId),
              user_id: userId,
              username: user.username,
              avatar: user.avatar,
              role: user.role,
              message: message,
              attachment: attachment,
              is_internal: isInternal ? 1 : 0,
              created_at: new Date().toISOString()
            };

            // Emit socket event
            io.to(`ticket-${ticketId}`).emit('newMessage', messageData);

            // Log activity
            await logActivity('ticket_message', `Added message to ticket #${ticketId}`, userId);

            res.json({
              success: true,
              message: 'Message sent successfully',
              data: messageData
            });
          });
        }
      );
    }
  );
});

app.put('/api/tickets/:id', requireAuth, (req, res) => {
  const ticketId = req.params.id;
  const { status, assigned_to, priority } = req.body;

  if (!status && !assigned_to && !priority) {
    return res.status(400).json({ 
      success: false, 
      message: 'No updates provided' 
    });
  }

  // Build update query dynamically
  let updates = [];
  let params = [];

  if (status) {
    updates.push('status = ?');
    params.push(status);
  }

  if (assigned_to) {
    updates.push('assigned_to = ?');
    params.push(assigned_to);
  }

  if (priority) {
    updates.push('priority = ?');
    params.push(priority);
  }

  // Add updated_at timestamp
  updates.push('updated_at = CURRENT_TIMESTAMP');
  
  // If closing ticket, add closed_at
  if (status === 'closed') {
    updates.push('closed_at = CURRENT_TIMESTAMP');
  }

  params.push(ticketId);

  const query = `UPDATE tickets SET ${updates.join(', ')} WHERE id = ?`;

  db.run(query, params, async function(err) {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ 
        success: false, 
        message: 'Failed to update ticket' 
      });
    }

    if (this.changes === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Ticket not found' 
      });
    }

    // Get updated ticket info for notification
    db.get('SELECT user_id, title FROM tickets WHERE id = ?', [ticketId], async (err, ticket) => {
      if (!err && ticket) {
        // Create notification for ticket owner
        let notificationMessage = '';
        if (status) {
          notificationMessage = `Your ticket "${ticket.title}" has been ${status}`;
        } else if (assigned_to) {
          notificationMessage = `Your ticket "${ticket.title}" has been assigned to an agent`;
        }

        if (notificationMessage) {
          db.run(
            'INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)',
            [ticket.user_id, 'Ticket Updated', notificationMessage, 'info']
          );
        }

        // Log activity
        await logActivity('ticket_updated', `Updated ticket #${ticketId}`, req.user.id, { updates });

        // Emit socket event
        io.to(`ticket-${ticketId}`).emit('ticketUpdated', {
          ticketId,
          status,
          assigned_to,
          priority,
          updatedBy: req.user.name,
          timestamp: new Date().toISOString()
        });
      }
    });

    res.json({
      success: true,
      message: 'Ticket updated successfully'
    });
  });
});

// Contact Form Route
app.post('/api/contact', requireAuth, (req, res) => {
  const { name, email, subject, message } = req.body;
  const userId = req.user.id;

  if (!name || !email || !subject || !message) {
    return res.status(400).json({ 
      success: false, 
      message: 'All fields are required' 
    });
  }

  db.run(
    'INSERT INTO contact_messages (user_id, name, email, subject, message) VALUES (?, ?, ?, ?, ?)',
    [userId, name, email, subject, message],
    function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Failed to send message' 
        });
      }

      // Log activity
      logActivity('contact_form', `Submitted contact form: ${subject}`, userId);

      res.json({
        success: true,
        message: 'Message sent successfully'
      });
    }
  );
});

// Careers Routes
app.get('/api/careers', (req, res) => {
  const status = req.query.status || 'active';
  const limit = parseInt(req.query.limit) || 20;
  const page = parseInt(req.query.page) || 1;
  const offset = (page - 1) * limit;

  let query = `
    SELECT id, job_id, title, department, type, location, employment_type, 
           salary, experience, description, status, posted_date, deadline, views
    FROM careers
    WHERE status = ?
    ORDER BY posted_date DESC
    LIMIT ? OFFSET ?
  `;

  db.all(query, [status, limit, offset], (err, jobs) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ 
        success: false, 
        message: 'Database error' 
      });
    }

    // Get total count
    db.get('SELECT COUNT(*) as total FROM careers WHERE status = ?', [status], (err, countResult) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error' 
        });
      }

      res.json({
        success: true,
        data: jobs || [],
        pagination: {
          page,
          limit,
          total: countResult.total,
          totalPages: Math.ceil(countResult.total / limit)
        }
      });
    });
  });
});

app.get('/api/careers/:id', (req, res) => {
  const jobId = req.params.id;

  // Increment views
  db.run('UPDATE careers SET views = views + 1 WHERE id = ? OR job_id = ?', [jobId, jobId]);

  db.get(
    `SELECT id, job_id, title, department, type, location, employment_type, 
            salary, experience, description, full_description, requirements, 
            benefits, status, posted_date, deadline, views
     FROM careers
     WHERE id = ? OR job_id = ?`,
    [jobId, jobId],
    (err, job) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error' 
        });
      }

      if (!job) {
        return res.status(404).json({ 
          success: false, 
          message: 'Job not found' 
        });
      }

      res.json({
        success: true,
        data: job
      });
    }
  );
});

app.post('/api/careers/:id/apply', upload.single('resume'), (req, res) => {
  const jobId = req.params.id;
  const { name, email, phone, cover_letter } = req.body;
  const resume = req.file ? req.file.filename : null;

  if (!name || !email || !cover_letter) {
    return res.status(400).json({ 
      success: false, 
      message: 'Name, email and cover letter are required' 
    });
  }

  // Check if job exists
  db.get('SELECT job_id, title FROM careers WHERE id = ? OR job_id = ?', [jobId, jobId], (err, job) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ 
        success: false, 
        message: 'Database error' 
      });
    }

    if (!job) {
      return res.status(404).json({ 
        success: false, 
        message: 'Job not found' 
      });
    }

    // Check if already applied
    db.get(
      'SELECT id FROM job_applications WHERE job_id = ? AND applicant_email = ?',
      [job.job_id, email],
      (err, existing) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ 
            success: false, 
            message: 'Database error' 
          });
        }

        if (existing) {
          return res.status(400).json({ 
            success: false, 
            message: 'You have already applied for this position' 
          });
        }

        // Submit application
        db.run(
          `INSERT INTO job_applications (job_id, applicant_name, applicant_email, applicant_phone, cover_letter, resume_path)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [job.job_id, name, email, phone, cover_letter, resume],
          function(err) {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ 
                success: false, 
                message: 'Failed to submit application' 
              });
            }

            // Log activity
            logActivity('job_application', `Applied for job: ${job.title}`, null, { email, jobId });

            res.json({
              success: true,
              message: 'Application submitted successfully'
            });
          }
        );
      }
    );
  });
});

// Admin Routes
app.get('/api/admin/dashboard', requireAdmin, (req, res) => {
  const getCount = (query, params = []) => {
    return new Promise((resolve, reject) => {
      db.get(query, params, (err, result) => {
        if (err) reject(err);
        else resolve(result ? result.count : 0);
      });
    });
  };

  Promise.all([
    getCount('SELECT COUNT(*) as count FROM users'),
    getCount('SELECT COUNT(*) as count FROM tickets WHERE status = ?', ['open']),
    getCount('SELECT COUNT(*) as count FROM tickets WHERE status = ?', ['closed']),
    getCount('SELECT COUNT(*) as count FROM contact_messages WHERE status = ?', ['pending']),
    getCount('SELECT COUNT(*) as count FROM job_applications WHERE status = ?', ['pending']),
    getCount('SELECT COUNT(*) as count FROM careers WHERE status = ?', ['active'])
  ])
  .then(([totalUsers, openTickets, closedTickets, pendingMessages, pendingApplications, activeJobs]) => {
    res.json({
      success: true,
      data: {
        totalUsers,
        openTickets,
        closedTickets,
        pendingMessages,
        pendingApplications,
        activeJobs,
        systemHealth: 95 + Math.random() * 5,
        uptime: 99.9,
        responseTime: (Math.random() * 50 + 20).toFixed(2)
      }
    });
  })
  .catch(err => {
    console.error('Database error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Database error' 
    });
  });
});

// Uptime Monitoring Routes
app.get('/api/services', async (req, res) => {
  try {
    db.all(
      'SELECT * FROM services ORDER BY created_at DESC',
      (err, services) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ 
            success: false, 
            message: 'Database error' 
          });
        }

        res.json({
          success: true,
          data: services || []
        });
      }
    );
  } catch (error) {
    console.error('Error loading services:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to load services' 
    });
  }
});

app.post('/api/services', requireAdmin, async (req, res) => {
  try {
    const { name, url } = req.body;

    if (!name || !url) {
      return res.status(400).json({ 
        success: false, 
        message: 'Name and URL are required' 
      });
    }

    // Validate URL
    try {
      new URL(url);
    } catch (error) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid URL format' 
      });
    }

    const jobId = `SRV-${Date.now()}-${Math.random().toString(36).substr(2, 4).toUpperCase()}`;

    db.run(
      'INSERT INTO services (job_id, name, url, status) VALUES (?, ?, ?, ?)',
      [jobId, name, url, 'unknown'],
      function(err) {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ 
            success: false, 
            message: 'Failed to add service' 
          });
        }

        res.json({
          success: true,
          message: 'Service added successfully',
          serviceId: this.lastID
        });
      }
    );
  } catch (error) {
    console.error('Error adding service:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to add service' 
    });
  }
});

// Service monitoring function
const checkServiceStatus = async (service) => {
  const startTime = Date.now();
  
  try {
    const response = await axios.get(service.url, { 
      timeout: 10000,
      validateStatus: function (status) {
        return status >= 200 && status < 600;
      }
    });
    
    const responseTime = Date.now() - startTime;
    let status = 'operational';
    
    if (responseTime > 5000) {
      status = 'slow';
    } else if (responseTime > 2000) {
      status = 'degraded';
    } else if (response.status >= 400) {
      status = 'down';
    }
    
    // Update service status in database
    db.run(
      'UPDATE services SET status = ?, response_time = ?, last_checked = CURRENT_TIMESTAMP WHERE id = ?',
      [status, responseTime, service.id]
    );
    
    return {
      ...service,
      status,
      responseTime
    };
  } catch (error) {
    // Update service status to down
    db.run(
      'UPDATE services SET status = ?, response_time = ?, last_checked = CURRENT_TIMESTAMP WHERE id = ?',
      ['down', 0, service.id]
    );
    
    return {
      ...service,
      status: 'down',
      responseTime: 0
    };
  }
};

// Monitor all services periodically
const monitorServices = async () => {
  try {
    db.all('SELECT * FROM services', async (err, services) => {
      if (err) {
        console.error('Error fetching services:', err);
        return;
      }

      for (const service of services) {
        await checkServiceStatus(service);
      }
      
      console.log('✅ Services monitoring completed');
    });
  } catch (error) {
    console.error('Error in service monitoring:', error);
  }
};

// HTML Pages Routes
app.get('/home', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/status', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'status.html'));
});

app.get('/careers', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'careers.html'));
});

app.get('/admin-tickets', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin-tickets.html'));
});

app.get('/create-ticket', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'Create-Ticket.html'));
});

app.get('/tickets', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'Tickets.html'));
});

// Serve auth pages
app.get('/auth/:page', (req, res) => {
  const page = req.params.page;
  const validPages = ['login', 'register', 'forgot-password'];
  
  if (validPages.includes(page)) {
    res.sendFile(path.join(__dirname, 'public', 'auth', `${page}.html`));
  } else {
    res.status(404).send('Page not found');
  }
});

// Serve main HTML files
app.get('/:page', (req, res) => {
  const page = req.params.page;
  const validPages = ['index', 'about', 'contact', 'services', 'security', 'tools', 'pricing'];
  
  if (validPages.includes(page)) {
    res.sendFile(path.join(__dirname, 'public', `${page}.html`));
  } else {
    // If not a known page, check if it's a file
    const filePath = path.join(__dirname, 'public', page);
    fsSync.access(filePath, fsSync.constants.F_OK, (err) => {
      if (err) {
        // File doesn't exist, redirect to home or show 404
        if (req.session.user) {
          return res.redirect('/home');
        } else {
          return res.redirect('/');
        }
      } else {
        res.sendFile(filePath);
      }
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err.stack);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      success: false,
      message: `File upload error: ${err.message}`
    });
  }
  
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use((req, res) => {
  if (req.accepts('html')) {
    if (req.session.user) {
      return res.redirect('/home');
    } else {
      return res.redirect('/');
    }
  }
  
  if (req.accepts('json')) {
    return res.status(404).json({
      success: false,
      message: 'Endpoint not found'
    });
  }
  
  res.status(404).send('Not found');
});

// =============================
// Start Server
// =============================
const startServer = async () => {
  try {
    // Ensure all directories exist
    await ensureDirExists(DATA_DIR);
    await ensureDirExists(path.join(__dirname, 'uploads'));
    await ensureDirExists(path.join(__dirname, 'public'));
    await ensureDirExists(path.join(__dirname, 'css'));
    await ensureDirExists(path.join(__dirname, 'js'));
    await ensureDirExists(path.join(__dirname, 'public', 'auth'));

    // Initialize database
    await initializeDatabase();
    console.log('✅ Database initialized successfully');

    // Start service monitoring
    monitorServices();
    setInterval(monitorServices, 5 * 60 * 1000); // Check every 5 minutes

    // Start the server
    server.listen(PORT, () => {
      console.log('\n' + '='.repeat(50));
      console.log('🚀 WAILAND SECURITY PLATFORM');
      console.log('='.repeat(50));
      console.log(`📊 Server running on: http://localhost:${PORT}`);
      console.log(`🗄️  Database: ${DB_PATH}`);
      console.log(`📁 Data directory: ${DATA_DIR}`);
      console.log(`🔐 Authentication: JWT & Session-based`);
      console.log(`💼 Careers system: Active`);
      console.log(`🎫 Ticket system: Ready`);
      console.log(`🔧 Security tools: Online`);
      console.log(`📈 Uptime monitoring: Active`);
      console.log(`🕒 Service monitoring: Every 5 minutes`);
      console.log('='.repeat(50) + '\n');
    });

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use.`);
        console.log(`💡 Try: kill -9 $(lsof -t -i:${PORT})`);
        process.exit(1);
      } else {
        console.error('❌ Server error:', err);
        process.exit(1);
      }
    });

  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();