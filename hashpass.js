// hashPassword.js

const bcrypt = require('bcrypt');
const readline = require('readline');

// Create an interface to read from command line
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Ask the user for a password
rl.question('Enter password to hash: ', (password) => {
  const saltRounds = 10;

  // Hash the password
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err);
      rl.close();
    } else {
      console.log('Hashed password:', hash);
      rl.close();
    }
  });
});
