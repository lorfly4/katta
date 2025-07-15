const express = require('express');
const path = require('path');
const session = require('express-session');
const bodyParser = require('body-parser');

const app = express();

// Setup view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const expressLayouts = require('express-ejs-layouts');
app.use(expressLayouts);
app.set('layout', 'layouts/template'); // default layout


// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: '38d753ec511900733ab3f155ae12167919476f59bced93a45aa985e8ea015d8c95b9426ad97ac316e5bb75e3d832ee0f133fbb97a670a6a1e48bb07d64fa8ff0',
    resave: false,
    saveUninitialized: false
}));

// Routes
const router = require('./routes/index');
app.use('/', router);

// Start server
app.listen(3000, () => {
    console.log('Server running at http://localhost:3000');
});
