const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

// Admin file path
const ADMINS_FILE = path.join(__dirname, 'data', 'admins.json');

// Ensure data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// New hashed password
async function resetAdmin() {
    try {
        const hashedPassword = await bcrypt.hash('admin123', 12);

        const adminData = [
            {
                email: 'admin@wailand.com',
                password: hashedPassword,
                name: 'System Administrator',
                role: 'admin',
                createdAt: new Date().toISOString()
            }
        ];

        fs.writeFileSync(ADMINS_FILE, JSON.stringify(adminData, null, 2));
        console.log('✅ Admin reset successfully!');
        console.log('📧 Email: admin@wailand.com');
        console.log('🔐 Password: admin123');
        console.log('🔑 Hashed password:', hashedPassword);
    } catch (error) {
        console.error('❌ Reset error:', error);
    }
}

resetAdmin();