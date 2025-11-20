const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

// مسار ملف الأدمن
const ADMINS_FILE = path.join(__dirname, 'data', 'admins.json');

// تأكد من وجود مجلد data
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// كلمة السر الجديدة المشفرة
async function resetAdmin() {
    try {
        const hashedPassword = await bcrypt.hash('admin123', 12);
        
        const adminData = [
            {
                email: 'admin@wailand.com',
                password: hashedPassword,
                name: 'مدير النظام',
                role: 'admin',
                createdAt: new Date().toISOString()
            }
        ];
        
        fs.writeFileSync(ADMINS_FILE, JSON.stringify(adminData, null, 2));
        console.log('✅ تم إعادة تعيين الأدمن بنجاح!');
        console.log('📧 البريد: admin@wailand.com');
        console.log('🔐 كلمة السر: admin123');
        console.log('🔑 كلمة السر المشفرة:', hashedPassword);
    } catch (error) {
        console.error('❌ خطأ في إعادة التعيين:', error);
    }
}

resetAdmin();