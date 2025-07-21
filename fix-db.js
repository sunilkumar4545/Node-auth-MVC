// Fix database index issue
const mongoose = require('mongoose');
require('dotenv').config();

async function fixDatabase() {
  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGO_URI);
    
    console.log('Dropping problematic email index...');
    const db = mongoose.connection.db;
    
    try {
      await db.collection('users').dropIndex('email_1');
      console.log('Email index dropped successfully');
    } catch (error) {
      console.log('Index may not exist or already dropped:', error.message);
    }
    
    console.log('Database fixed! You can now register users.');
    process.exit(0);
  } catch (error) {
    console.error('Error fixing database:', error);
    process.exit(1);
  }
}

fixDatabase();
