const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.static('.'));

// الملفات
const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const ADMINS_FILE = path.join(__dirname, 'data', 'admins.json');
const TOKENS_FILE = path.join(__dirname, 'data', 'tokens.json');
const USER_DATA_FILE = path.join(__dirname, 'data', 'user-data.json');

// إنشاء مجلد data
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// قراءة وكتابة JSON
function readJSON(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      return null;
    }
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

// تهيئة الملفات
function initializeFiles() {
  if (!fs.existsSync(USERS_FILE)) {
    writeJSON(USERS_FILE, []);
    console.log('تم إنشاء ملف المستخدمين');
  }
  if (!fs.existsSync(ADMINS_FILE)) {
    // إضافة أدمن افتراضي
    const hashedPassword = bcrypt.hashSync('admin123', 12);
    writeJSON(ADMINS_FILE, [
      {
        email: 'admin@wailand.com',
        password: hashedPassword,
        name: 'مدير النظام',
        role: 'admin',
        createdAt: new Date().toISOString()
      }
    ]);
    console.log('تم إنشاء ملف الأدمن مع أدمن افتراضي');
  }
  if (!fs.existsSync(TOKENS_FILE)) {
    writeJSON(TOKENS_FILE, {});
    console.log('تم إنشاء ملف التوكنات');
  }
  if (!fs.existsSync(USER_DATA_FILE)) {
    writeJSON(USER_DATA_FILE, {});
    console.log('تم إنشاء ملف بيانات المستخدمين');
  }
}

// إنشاء بيانات افتراضية للمستخدم
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
      dataProcessed: Math.floor(Math.random() * 1500) + 500
    },
    tools: [
      {
        id: 1,
        name: 'Vulnerability Scanner',
        description: 'Scan your systems for security vulnerabilities and potential threats.',
        status: 'online',
        icon: 'fas fa-search',
        usage: Math.floor(Math.random() * 30) + 70
      },
      {
        id: 2,
        name: 'Password Auditor',
        description: 'Check the strength of your passwords and get recommendations.',
        status: 'online',
        icon: 'fas fa-lock',
        usage: Math.floor(Math.random() * 30) + 60
      },
      {
        id: 3,
        name: 'Firewall Manager',
        description: 'Configure and monitor your firewall settings in real-time.',
        status: 'online',
        icon: 'fas fa-shield-alt',
        usage: Math.floor(Math.random() * 20) + 75
      },
      {
        id: 4,
        name: 'Penetration Test',
        description: 'Simulate cyber attacks to test your system\'s defenses.',
        status: Math.random() > 0.7 ? 'warning' : 'online',
        icon: 'fas fa-bug',
        usage: Math.floor(Math.random() * 40) + 40
      }
    ],
    notifications: [
      {
        id: 1,
        title: 'System security scan completed successfully',
        message: 'The latest security scan detected no critical threats in your system.',
        type: 'success',
        timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
        read: false
      },
      {
        id: 2,
        title: 'Welcome to Wailand Security System',
        message: 'Your account has been successfully activated.',
        type: 'info',
        timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        read: true
      }
    ],
    profile: {
      scans: Math.floor(Math.random() * 200) + 50,
      tools: Math.floor(Math.random() * 6) + 2,
      daysActive: Math.floor(Math.random() * 100) + 30
    }
  };
}

// 🔐 API: تسجيل الدخول الحقيقي
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  console.log('🔐 محاولة تسجيل دخول ل:', email);
  
  if (!email || !password) {
    return res.status(400).json({ message: 'البريد الإلكتروني وكلمة السر مطلوبان' });
  }
  
  try {
    // البحث في الأدمن أولاً
    const admins = readJSON(ADMINS_FILE) || [];
    const admin = admins.find(a => a.email === email);
    
    if (admin) {
      const isPasswordValid = await bcrypt.compare(password, admin.password);
      if (isPasswordValid) {
        console.log('✅ تم تسجيل دخول أدمن:', email);
        
        // إنشاء بيانات الأدمن إذا لم تكن موجودة
        const userData = readJSON(USER_DATA_FILE) || {};
        if (!userData[admin.email]) {
          userData[admin.email] = createDefaultUserData(admin.email);
          writeJSON(USER_DATA_FILE, userData);
        }
        
        return res.json({
          message: 'تم تسجيل الدخول بنجاح',
          user: {
            id: admin.email,
            name: admin.name,
            email: admin.email,
            role: 'admin',
            isAdmin: true
          },
          redirectTo: 'admin-dashboard.html'
        });
      }
    }
    
    // البحث في المستخدمين العاديين
    const users = readJSON(USERS_FILE) || [];
    const user = users.find(u => u.email === email);
    
    if (user) {
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (isPasswordValid) {
        console.log('✅ تم تسجيل دخول مستخدم:', email);
        
        // إنشاء بيانات المستخدم إذا لم تكن موجودة
        const userData = readJSON(USER_DATA_FILE) || {};
        if (!userData[user.id]) {
          userData[user.id] = createDefaultUserData(user.id);
          writeJSON(USER_DATA_FILE, userData);
        }
        
        return res.json({
          message: 'تم تسجيل الدخول بنجاح',
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: 'user',
            isAdmin: false
          },
          redirectTo: 'home.html'
        });
      }
    }
    
    console.log('❌ فشل تسجيل الدخول ل:', email);
    return res.status(401).json({ message: 'البريد الإلكتروني أو كلمة السر غير صحيحة' });
    
  } catch (error) {
    console.error('❌ خطأ في تسجيل الدخول:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// 📝 API: إنشاء حساب جديد حقيقي
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  
  console.log('📝 محاولة إنشاء حساب جديد:', email);
  
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'جميع الحقول مطلوبة' });
  }
  
  if (password.length < 8) {
    return res.status(400).json({ message: 'كلمة السر يجب أن تكون 8 أحرف على الأقل' });
  }
  
  try {
    const users = readJSON(USERS_FILE) || [];
    const admins = readJSON(ADMINS_FILE) || [];
    
    // التحقق إذا كان البريد مستخدم
    if (users.find(user => user.email === email) || admins.find(admin => admin.email === email)) {
      return res.status(409).json({ message: 'هذا البريد الإلكتروني مستخدم بالفعل' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const newUser = {
      id: crypto.randomUUID(),
      name,
      email,
      password: hashedPassword,
      role: 'user',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    users.push(newUser);
    
    if (writeJSON(USERS_FILE, users)) {
      // إنشاء بيانات المستخدم الجديد
      const userData = readJSON(USER_DATA_FILE) || {};
      userData[newUser.id] = createDefaultUserData(newUser.id);
      writeJSON(USER_DATA_FILE, userData);
      
      console.log('✅ تم إنشاء حساب جديد:', email);
      res.status(201).json({ 
        message: 'تم إنشاء الحساب بنجاح',
        user: { 
          id: newUser.id, 
          name: newUser.name, 
          email: newUser.email,
          role: 'user'
        }
      });
    } else {
      res.status(500).json({ message: 'فشل في إنشاء الحساب' });
    }
  } catch (error) {
    console.error('❌ خطأ في إنشاء الحساب:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// 📊 API: الحصول على بيانات الداشبورد للمستخدم الحالي
app.get('/api/dashboard/:userId', (req, res) => {
  const { userId } = req.params;
  
  try {
    const userData = readJSON(USER_DATA_FILE) || {};
    const user = userData[userId];
    
    if (user) {
      res.json(user.dashboard);
    } else {
      res.status(404).json({ message: 'لم يتم العثور على بيانات المستخدم' });
    }
  } catch (error) {
    console.error('❌ خطأ في جلب بيانات الداشبورد:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// 🔧 API: تحديث بيانات الداشبورد
app.put('/api/dashboard/:userId', (req, res) => {
  const { userId } = req.params;
  const updatedData = req.body;
  
  try {
    const userData = readJSON(USER_DATA_FILE) || {};
    
    if (userData[userId]) {
      userData[userId].dashboard = { ...userData[userId].dashboard, ...updatedData };
      
      if (writeJSON(USER_DATA_FILE, userData)) {
        res.json({ message: 'تم تحديث البيانات بنجاح' });
      } else {
        res.status(500).json({ message: 'فشل في تحديث البيانات' });
      }
    } else {
      res.status(404).json({ message: 'لم يتم العثور على المستخدم' });
    }
  } catch (error) {
    console.error('❌ خطأ في تحديث بيانات الداشبورد:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// 🛠️ API: الحصول على أدوات المستخدم
app.get('/api/tools/:userId', (req, res) => {
  const { userId } = req.params;
  
  try {
    const userData = readJSON(USER_DATA_FILE) || {};
    const user = userData[userId];
    
    if (user && user.tools) {
      res.json({ tools: user.tools });
    } else {
      res.status(404).json({ message: 'لم يتم العثور على الأدوات' });
    }
  } catch (error) {
    console.error('❌ خطأ في جلب الأدوات:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// 🔔 API: الحصول على إشعارات المستخدم
app.get('/api/notifications/:userId', (req, res) => {
  const { userId } = req.params;
  
  try {
    const userData = readJSON(USER_DATA_FILE) || {};
    const user = userData[userId];
    
    if (user && user.notifications) {
      res.json({ notifications: user.notifications });
    } else {
      res.status(404).json({ message: 'لم يتم العثور على الإشعارات' });
    }
  } catch (error) {
    console.error('❌ خطأ في جلب الإشعارات:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// 🔔 API: إضافة إشعار جديد
app.post('/api/notifications/:userId', (req, res) => {
  const { userId } = req.params;
  const { title, message, type } = req.body;
  
  try {
    const userData = readJSON(USER_DATA_FILE) || {};
    
    if (userData[userId]) {
      const newNotification = {
        id: Date.now(),
        title,
        message,
        type: type || 'info',
        timestamp: new Date().toISOString(),
        read: false
      };
      
      if (!userData[userId].notifications) {
        userData[userId].notifications = [];
      }
      
      userData[userId].notifications.unshift(newNotification);
      
      if (writeJSON(USER_DATA_FILE, userData)) {
        res.json({ message: 'تم إضافة الإشعار بنجاح', notification: newNotification });
      } else {
        res.status(500).json({ message: 'فشل في إضافة الإشعار' });
      }
    } else {
      res.status(404).json({ message: 'لم يتم العثور على المستخدم' });
    }
  } catch (error) {
    console.error('❌ خطأ في إضافة الإشعار:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// 👤 API: الحصول على بيانات البروفايل
app.get('/api/profile/:userId', (req, res) => {
  const { userId } = req.params;
  
  try {
    const userData = readJSON(USER_DATA_FILE) || {};
    const user = userData[userId];
    
    if (user && user.profile) {
      res.json({ profile: user.profile });
    } else {
      res.status(404).json({ message: 'لم يتم العثور على بيانات البروفايل' });
    }
  } catch (error) {
    console.error('❌ خطأ في جلب بيانات البروفايل:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// 📋 API: الحصول على جميع المستخدمين (للأدمن فقط)
app.get('/api/admin/users', (req, res) => {
  try {
    const users = readJSON(USERS_FILE) || [];
    
    // إزالة كلمات السر من النتيجة
    const usersWithoutPasswords = users.map(user => {
      const { password, ...userWithoutPassword } = user;
      return userWithoutPassword;
    });
    
    console.log('📋 تم جلب', usersWithoutPasswords.length, 'مستخدم');
    res.json({ users: usersWithoutPasswords });
  } catch (error) {
    console.error('❌ خطأ في جلب المستخدمين:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// 🌐 خدمة الملفات الثابتة
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.get('/home.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/home.html'));
});

app.get('/dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/dashboard.html'));
});

// بدء الخادم
app.listen(PORT, () => {
  initializeFiles();
  console.log('='.repeat(50));
  console.log('🚀 خادم Wailand يعمل على http://localhost:' + PORT);
  console.log('='.repeat(50));
  console.log('🔐 نظام المصادقة الحقيقي جاهز');
  console.log('👑 نظام الأدمن جاهز');
  console.log('👥 نظام المستخدمين جاهز');
  console.log('💾 تخزين البيانات الفردية جاهز');
  console.log('='.repeat(50));
  console.log('🔑 بيانات الدخول الافتراضية:');
  console.log('👑 الأدمن: admin@wailand.com / admin123');
  console.log('👤 أو أنشئ حساب جديد من صفحة التسجيل');
  console.log('='.repeat(50));
});