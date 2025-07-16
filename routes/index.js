  const express = require('express');
  const router = express.Router();
  const bcrypt = require('bcryptjs');
  const db = require('../db'); // koneksi mysql kamu (nanti kita bahas)
  const isAuthenticated = require('../middleware/auth');
  const Auth = require('../middleware/auth');

  // GET: Login page
  router.get('/', (req, res) => {
    // Jika user sudah login, arahkan ke dashboard
    if (req.session.user) return res.redirect('/dashboard');

    // Tampilkan login tanpa layout
    res.render('login', {
      layout: false
    });
  });

  router.get('/login', (req, res) => {
    res.render('login', {
      title: 'Login',
      layout: false
    });
  });


  // POST: Proses login
  router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
      const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

      if (rows.length === 0) {
        return res.render('login', { error: 'Email tidak ditemukan', title: 'Login', layout: false });
      }

      const user = rows[0];

      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return res.render('login', { error: 'Password salah', title: 'Login', layout: false });
      }

      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      };

      return res.redirect('/dashboard');
    } catch (err) {
      console.error(err);
      res.render('login', { error: 'Terjadi kesalahan server', title: 'Login', layout: false });
    }
  });

  // GET: Logout
  router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        console.error('Failed to destroy session during logout', err);
        return res.redirect('/dashboard');
      }
      res.clearCookie('connect.sid');
      res.redirect('/login');
    });
  });


  // GET: User (dilindungi, hanya admin yang bisa akses)
  router.get('/users', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') {
      return res.status(403).send('Forbidden');
    }

    const [rows] = await db.execute('SELECT * FROM users ORDER BY id DESC');
    res.render('user', { title: 'Daftar User', user: req.session.user, user: rows });
  });

  router.get('/users/tambah', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') {
      return res.status(403).send('Forbidden');
    }

    const [rows] = await db.execute('SELECT * FROM users ORDER BY id DESC');
    res.render('user-tambah', { title: 'Daftar User', user: req.session.user, user: rows });
  });

  // POST: Tambah user (dilindungi, hanya admin yang bisa akses)
  router.post('/users/tambah', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') {
      return res.status(403).send('Forbidden');
    }

    const { name, email, password, role } = req.body;

    try {
      const passwordHash = await bcrypt.hash(password, 10);
      await db.execute('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)', [name, email, passwordHash, role]);

      res.redirect('/users');
    } catch (err) {
      console.error(err);
      res.render('user', { error: 'Terjadi kesalahan server', title: 'Daftar User', user: req.session.user, user: rows });
    }
  });
  // GET: Dashboard (dilindungi)
  router.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard', {
      title: 'Dashboard',
      user: req.session.user
    });
  });

  // LIST KLIIEN
  router.get('/clients', isAuthenticated, async (req, res) => {
    const [rows] = await db.execute('SELECT * FROM clients ORDER BY id DESC');
    res.render('clients', { title: 'Daftar Klien', user: req.session.user, clients: rows });
  });

  // TAMBAH KLIEN
  router.post('/clients', isAuthenticated, async (req, res) => {
    const { name, company, phone, email } = req.body;
    await db.execute('INSERT INTO clients (name, company, phone, email) VALUES (?, ?, ?, ?)', [name, company, phone, email]);
    res.redirect('/clients');
  });

  // LIST INTERAKSI
  router.get('/interactions', isAuthenticated, async (req, res) => {
    const [rows] = await db.execute(`
      SELECT interactions.*, clients.name AS client_name
      FROM interactions
      JOIN clients ON interactions.client_id = clients.id
      ORDER BY interactions.id DESC
    `);
    const [clients] = await db.execute('SELECT id, name FROM clients');
    res.render('interactions', { title: 'Daftar Interaksi', user: req.session.user, interactions: rows, clients });
  });

  // TAMBAH INTERAKSI
  router.post('/interactions', isAuthenticated, async (req, res) => {
    const { client_id, type, notes } = req.body;
    await db.execute('INSERT INTO interactions (client_id, type, notes) VALUES (?, ?, ?)', [client_id, type, notes]);
    res.redirect('/interactions');
  });

  // LIST PENJUALAN
  router.get('/penjualan', isAuthenticated, (req, res) => {
    res.render('penjualan/overview', { title: 'Penjualan', user: req.session.user });
  });

  router.get('/penjualan/tagihan', isAuthenticated, (req, res) => {
    res.render('penjualan/tagihan', { title: 'Tagihan', user: req.session.user });
  });

  router.get('/penjualan/pengiriman', isAuthenticated, (req, res) => {
    res.render('penjualan/pengiriman', { title: 'Pengiriman', user: req.session.user });
  });

  router.get('/penjualan/pemesanan', isAuthenticated, (req, res) => {
    res.render('penjualan/pemesanan', { title: 'Pemesanan', user: req.session.user });
  });

  router.get('/penjualan/penawaran', isAuthenticated, (req, res) => {
    res.render('penjualan/penawaran', { title: 'Penawaran', user: req.session.user });
  });

  router.get('/pembelian', isAuthenticated, (req, res) => {
    res.render('pembelian/overview', { title: 'Pembelian', user: req.session.user });
  });

  router.get('/pembelian/tagihan', isAuthenticated, (req, res) => {
    res.render('pembelian/tagihan', { title: 'Tagihan', user: req.session.user });
  });

  router.get('/pembelian/pengiriman', isAuthenticated, (req, res) => {
    res.render('pembelian/pengiriman', { title: 'Pengiriman', user: req.session.user });
  });

  router.get('/pembelian/pemesanan', isAuthenticated, (req, res) => {
    res.render('pembelian/pemesanan', { title: 'Pemesanan', user: req.session.user });
  });

  router.get('/pembelian/penawaran', isAuthenticated, (req, res) => {
    res.render('pembelian/penawaran', { title: 'Penawaran', user: req.session.user });
  });

  router.get('/biaya', isAuthenticated, (req,res) => {
    res.render('biaya', { title: 'Biaya', user: req.session.user });
  });
  router.get('/produk', isAuthenticated, (req,res) => {
    res.render('produk', { title: 'produk', user: req.session.user });
  });
  router.get('/inventori', isAuthenticated, (req,res) => {
    res.render('inventori', { title: 'inventori', user: req.session.user });
  });
  router.get('/laporan', isAuthenticated, (req,res) => {
    res.render('laporan', { title: 'laporan', user: req.session.user });
  });
  router.get('/kas-bank', isAuthenticated, (req,res) => {
    res.render('kas-bank', { title: 'kas-bank', user: req.session.user });
  });


  module.exports = router;
