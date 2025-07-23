const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const db = require("../db"); // koneksi mysql kamu (nanti kita bahas)
const isAuthenticated = require("../middleware/auth");
const multer = require("multer");
const path = require("path");
const nodemailer = require('nodemailer');


// Konfigurasi multer untuk simpan file di public/img
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, "../public/img"));
  },
  filename: function (req, file, cb) {
    // Simpan dengan nama unik (timestamp + originalname)
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + "-" + file.originalname);
  },
});
const upload = multer({ storage: storage });

// GET: Login page
router.get("/", (req, res) => {
  // Jika user sudah login, arahkan ke dashboard
  if (req.session.user) return res.redirect("/dashboard");

  // Tampilkan login tanpa layout
  res.render("login", {
    layout: false,
  });
});

router.get("/login", (req, res) => {
  res.render("login", {
    title: "Login",
    layout: false,
  });
});

// POST: Proses login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.execute("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (rows.length === 0) {
      return res.render("login", {
        error: "Email tidak ditemukan",
        title: "Login",
        layout: false,
      });
    }

    const user = rows[0];

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.render("login", {
        error: "Password salah",
        title: "Login",
        layout: false,
      });
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    return res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.render("login", {
      error: "Terjadi kesalahan server",
      title: "Login",
      layout: false,
    });
  }
});

// GET: Logout
router.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Failed to destroy session during logout", err);
      return res.redirect("/dashboard");
    }
    res.clearCookie("connect.sid");
    res.redirect("/login");
  });
});

// GET: User (dilindungi, hanya admin yang bisa akses)
router.get("/users", isAuthenticated, async (req, res) => {
  if (req.session.user.role !== "admin") {
    return res.status(403).send("Forbidden");
  }

  const [rows] = await db.execute("SELECT * FROM users ORDER BY id DESC");
  res.render("user", {
    title: "Daftar User",
    user: req.session.user,
    user: rows,
  });
});

router.get("/users/tambah", isAuthenticated, async (req, res) => {
  if (req.session.user.role !== "admin") {
    return res.status(403).send("Forbidden");
  }

  const [rows] = await db.execute("SELECT * FROM users ORDER BY id DESC");
  res.render("user-tambah", {
    title: "Daftar User",
    user: req.session.user,
    user: rows,
  });
});

// POST: Tambah user (dilindungi, hanya admin yang bisa akses)
router.post("/users/tambah", isAuthenticated, async (req, res) => {
  if (req.session.user.role !== "admin") {
    return res.status(403).send("Forbidden");
  }

  const { name, email, password, role } = req.body;

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    await db.execute(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
      [name, email, passwordHash, role]
    );

    res.redirect("/users");
  } catch (err) {
    console.error(err);
    res.render("user", {
      error: "Terjadi kesalahan server",
      title: "Daftar User",
      user: req.session.user,
      user: rows,
    });
  }
});
// GET: Dashboard (dilindungi)
router.get("/dashboard", isAuthenticated, (req, res) => {
  res.render("dashboard", {
    title: "Dashboard",
    user: req.session.user,
  });
});

// LIST KLIIEN
router.get('/clients', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
    return res.status(403).send('Forbidden');
  }

  const [rows] = await db.execute(`
    SELECT clients.*, users.name AS creator_name
    FROM clients
    LEFT JOIN users ON clients.created_by = users.id
    ORDER BY clients.id DESC
  `);
  res.render('crm/table/klien', { title: 'Daftar Klien', user: req.session.user, clients: rows });
});

// CREATE KLIEN
router.get('/crm/backend/createklien', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
    return res.status(403).send('Forbidden');
  }

  const [rows] = await db.execute('SELECT * FROM clients ORDER BY id DESC');
  res.render('crm/backend/createklien', { title: 'Daftar Klien', user: req.session.user, clients: rows });
});

// TAMBAH KLIEN
router.post('/clients', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
    return res.status(403).send('Forbidden');
  }

  const { nama_klien: name, perusahaan_klien: company, nomor_telpon_klien: phone, email_klien: email } = req.body;
  await db.execute('INSERT INTO clients (name, company, phone, email, created_by) VALUES (?, ?, ?, ?, ?)', [name, company, phone, email, req.session.user.id]);
  res.redirect('/clients');
});


// EDIT KLIEN
router.get('/clients/edit/:id', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
    return res.status(403).send('Forbidden');
  }

  const [rows] = await db.execute('SELECT * FROM clients WHERE id = ?', [req.params.id]);
  if (rows.length === 0) return res.status(404).send('Not found');
  res.render('crm/backend/editklien', { title: 'Edit Klien', user: req.session.user, client: rows[0] });
});

// UPDATE KLIEN
router.post('/clients/edit/:id', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
    return res.status(403).send('Forbidden');
  }

  const { nama_klien, perusahaan_klien, nomor_telpon_klien, email_klien } = req.body;
  await db.execute('UPDATE clients SET name = ?, company = ?, phone = ?, email = ? WHERE id = ?', [nama_klien, perusahaan_klien, nomor_telpon_klien, email_klien, req.params.id]);
  res.redirect('/clients');
});

// HAPUS KLIEN
router.post('/clients/delete/:id', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
    return res.status(403).send('Forbidden');
  }
  await db.execute('DELETE FROM clients WHERE id = ?', [req.params.id]);
  res.redirect('/clients');
});




// =========================================================================================================

// LIST INTERAKSI
router.get('/interactions', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
    return res.status(403).send('Forbidden');
  }

  const [rows] = await db.execute(`
  SELECT interactions.*, clients.name AS client_name, users.name AS created_by_name
  FROM interactions
  JOIN clients ON interactions.client_id = clients.id
  JOIN users ON interactions.created_by = users.id
  ORDER BY interactions.id DESC
`);

  const [clients] = await db.execute('SELECT id, name FROM clients');

  res.render('crm/table/interaksi', {
    title: 'Daftar Interaksi',
    user: req.session.user,
    interactions: rows,
    clients
  });
});

// TAMBAH INTERAKSI
router.get('/interactions/tambah', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
    return res.status(403).send('Forbidden');
  }

  const [clients] = await db.execute('SELECT id, name FROM clients');
  res.render('crm/backend/createinteraksiklien', { title: 'Daftar Interaksi', user: req.session.user, clients });
});


// TAMBAH INTERAKSI
router.post('/interactions', isAuthenticated, upload.single('attachment'), async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
    return res.status(403).send('Forbidden');
  }

  const { client_id, type, notes, send_email, subjek } = req.body;
  const file = req.file;

  // Simpan interaksi ke database
  const [client] = await db.execute('SELECT email FROM clients WHERE id = ?', [client_id]);
  const email = client[0]?.email;

  await db.execute(`
  INSERT INTO interactions (user_id, client_id, type, subjek, notes, file_path, send_email, created_by)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`,
    [
      req.session.user.id,
      client_id,
      type,
      subjek,
      notes,
      file?.path || null,
      send_email ? 1 : 0,
      req.session.user.id
    ]);


  // Jika opsi kirim email dicentang

  if (send_email && email) {
    try {
      // Ambil username dan password dari tabel konfig_email
      const [rows] = await db.execute('SELECT * FROM konfig_email LIMIT 1');

      if (!rows.length) {
        console.error("Konfigurasi email tidak ditemukan");
        return res.status(500).send('Konfigurasi email tidak ditemukan');
      }

      const { type, host, port, username, password } = rows[0];

      let transporter;
      if (type === 'gmail') {
        transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
            user: username,
            pass: password
          }
        });
      } else if (type === 'smtp') {
        transporter = nodemailer.createTransport({
          host,
          port,
          auth: {
            user: username,
            pass: password
          }
        });
      } else {
        return res.status(500).send('Tidak support untuk pengiriman email dari provider lain');
      }
      const mailOptions = {
        from: 'noreply',
        to: email, // Ganti dengan variabel email yang dikirim
        subject: subjek,
        text: notes,
        attachments: file ? [{
          filename: file.originalname,
          path: file.path
        }] : []
      };

      await transporter.sendMail(mailOptions);
      console.log('Email dikirim ke:', email);

    } catch (err) {
      console.error('Gagal kirim email:', err);
    }
  }

  res.redirect('/interactions');

});

// KONFIGURASI EMAIL 


router.get('/email', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }

  const [emailConfig] = await db.execute('SELECT * FROM konfig_email WHERE id_user = ?', [req.session.user.id]);
  const [users] = await db.execute('SELECT id, name FROM users');

  res.render('crm/backend/createconfigemail', {
    title: 'Email',
    user: req.session.user,
    emailConfig: emailConfig[0] || {},
    users
  });
});



router.post('/prosesemail', isAuthenticated, async (req, res) => {
  const {
    email_host,
    email_port,
    email_username_smtp,
    email_password_smtp,
    email_username_gmail,
    email_password_gmail
  } = req.body;

  // Handle SMTP (jika username dan password SMTP diisi)
  if (email_username_smtp && email_password_smtp) {
    await db.execute(
      `INSERT INTO konfig_email (type, host, port, username, password, id_user)
     VALUES (?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE host = VALUES(host), port = VALUES(port), username = VALUES(username), password = VALUES(password), id_user = VALUES(id_user)`,
      ['smtp', email_host, email_port, email_username_smtp, email_password_smtp, req.session.user.id]
    );
  }

  // Handle Gmail (jika username dan password Gmail diisi)
  if (email_username_gmail && email_password_gmail) {
    await db.execute(
      `INSERT INTO konfig_email (type, host, port, username, password, id_user)
     VALUES (?, NULL, NULL, ?, ?, ?)
     ON DUPLICATE KEY UPDATE username = VALUES(username), password = VALUES(password), id_user = VALUES(id_user)`,
      ['gmail', email_username_gmail, email_password_gmail, req.session.user.id]
    );
  }

  res.redirect('/email');


});



// =========================================================================================================


// LIST PENJUALAN
router.get("/penjualan", isAuthenticated, (req, res) => {
  res.render("finance/penjualan/overview", {
    title: "Penjualan",
    user: req.session.user,
  });
});

router.get("/penjualan/tagihan", isAuthenticated, async (req, res) => {
  // Ambil query filter
  const { status, search, start_date, end_date } = req.query;

  // Query dasar
  let sql = "SELECT * FROM penjualan_tagihan WHERE 1=1";
  const params = [];

  // Filter status
  if (status) {
    sql += " AND status = ?";
    params.push(status);
  }

  // Filter search
  if (search) {
    sql += " AND (nomor LIKE ? OR pelanggan LIKE ?)";
    params.push(`%${search}%`, `%${search}%`);
  }

  // Filter tanggal
  if (start_date) {
    sql += " AND tanggal >= ?";
    params.push(start_date);
  }
  if (end_date) {
    sql += " AND tanggal <= ?";
    params.push(end_date);
  }

  sql += " ORDER BY id DESC";

  const [rows] = await db.execute(sql, params);

  res.render("finance/penjualan/tagihan", {
    title: "Tagihan",
    user: req.session.user,
    tagihan: rows,
    status, // <-- kirim status ke EJS
    search, // <-- kirim search ke EJS
    start_date, // <-- kirim start_date ke EJS
    end_date, // <-- kirim end_date ke EJS
  });
});

router.get("/penjualan/tagihan/create", isAuthenticated, (req, res) => {
  res.render("finance/penjualan/backend/createtagihan", {
    title: "Buat Tagihan",
    user: req.session.user,
  });
});

router.post("/penjualan/tagihan/create", isAuthenticated, async (req, res) => {
  try {
    const {
      nomor,
      pelanggan,
      referensi,
      tanggal,
      tgl_jatuh_tempo,
      status,
      sisa_tagihan,
      total,
    } = req.body;

    // Validasi input sederhana
    if (!nomor || !pelanggan || !tanggal || !total) {
      return res
        .status(400)
        .send("Data tidak lengkap. Pastikan semua input terisi.");
    }

    const query = `
      INSERT INTO penjualan_tagihan 
      (nomor, pelanggan, referensi, tanggal, tgl_jatuh_tempo, status, sisa_tagihan, total)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const values = [
      nomor,
      pelanggan,
      referensi,
      tanggal,
      tgl_jatuh_tempo,
      status,
      sisa_tagihan,
      total,
    ];

    const [result] = await db.execute(query, values);

    if (result.affectedRows > 0) {
      return res.redirect("/penjualan/tagihan");
    } else {
      return res.status(500).send("Data gagal ditambahkan ke database.");
    }
  } catch (error) {
    console.error("Terjadi kesalahan saat menyimpan tagihan:", error.message);
    return res.status(500).send("Terjadi kesalahan server: " + error.message);
  }
});

router.get("/penjualan/pengiriman", isAuthenticated, async (req, res) => {
  // Ambil query filter
  const { status, search, start_date, end_date } = req.query;

  // Query dasar
  let sql = "SELECT * FROM penjualan_pengiriman WHERE 1=1";
  const params = [];

  // Filter status
  if (status) {
    sql += " AND status = ?";
    params.push(status);
  }

  // Filter search
  if (search) {
    sql += " AND (nomor LIKE ? OR vendor LIKE ?)";
    params.push(`%${search}%`, `%${search}%`);
  }

  // Filter tanggal
  if (start_date) {
    sql += " AND tanggal >= ?";
    params.push(start_date);
  }
  if (end_date) {
    sql += " AND tanggal <= ?";
    params.push(end_date);
  }

  sql += " ORDER BY id DESC";

  const [rows] = await db.execute(sql, params);

  res.render("finance/penjualan/pengiriman", {
    title: "Pengiriman",
    user: req.session.user,
    pengiriman: rows,
    status,
    search,
    start_date,
    end_date,
  });
});

router.post("/penjualan/pengiriman", isAuthenticated, async (req, res) => {
  const { nomor, vendor, detail, referensi, tanggal, status } = req.body;

  // Check for missing fields
  if (!nomor || !vendor || !tanggal) {
    return res.status(400).send("Nomor, vendor, dan tanggal wajib diisi.");
  }

  try {
    const query = `
      INSERT INTO penjualan_pengiriman 
      (nomor, vendor, detail, referensi, tanggal, status)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    const values = [nomor, vendor, detail, referensi, tanggal, status];

    const [result] = await db.execute(query, values);
    res.redirect("/penjualan/pengiriman");
  } catch (error) {
    console.error("Error saat menyimpan pengiriman:", error.message);
    res.status(500).send("Terjadi kesalahan server.");
  }
});
router.get("/penjualan/pengiriman/create", isAuthenticated, (req, res) => {
  res.render("finance/penjualan/backend/createpengiriman", {
    title: "Tambah Pengiriman",
    user: req.session.user,
  });
});
router.get("/penjualan/pemesanan", isAuthenticated, async (req, res) => {
  const { status, search, start_date, end_date } = req.query;

  let sql = "SELECT * FROM penjualan_pemesanan WHERE 1=1";
  const params = [];

  if (status) {
    sql += " AND status = ?";
    params.push(status);
  }

  if (search) {
    sql += " AND (nomor LIKE ? OR vendor LIKE ?)";
    params.push(`%${search}%`, `%${search}%`);
  }

  if (start_date) {
    sql += " AND tanggal >= ?";
    params.push(start_date);
  }
  if (end_date) {
    sql += " AND tanggal <= ?";
    params.push(end_date);
  }

  sql += " ORDER BY id DESC";

  const [rows] = await db.execute(sql, params);

  res.render("finance/penjualan/pemesanan", {
    title: "Pemesanan",
    user: req.session.user,
    pemesanan: rows,
    status,
    search,
    start_date,
    end_date,
  });
});

router.get("/penjualan/pemesanan/create", isAuthenticated, (req, res) => {
  res.render("finance/penjualan/backend/createpemesanan", {
    title: "Buat Pemesanan",
    user: req.session.user,
  });
});

router.post(
  "/penjualan/pemesanan/create",
  isAuthenticated,
  async (req, res) => {
    try {
      const {
        nomor,
        vendor,
        referensi,
        tanggal,
        tgl_jatuh_tempo,
        status,
        sisa_tagihan,
        total,
      } = req.body;

      // Validasi input sederhana
      if (!nomor || !vendor || !tanggal || !total) {
        return res
          .status(400)
          .send("Data tidak lengkap. Pastikan semua input terisi.");
      }

      const query = `
      INSERT INTO penjualan_pemesanan 
      (nomor, vendor, referensi, tanggal, tgl_jatuh_tempo, status, sisa_tagihan, total)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

      const values = [
        nomor,
        vendor,
        referensi,
        tanggal,
        tgl_jatuh_tempo,
        status,
        sisa_tagihan,
        total,
      ];

      const [result] = await db.execute(query, values);

      if (result.affectedRows > 0) {
        return res.redirect("/penjualan/pemesanan");
      } else {
        return res.status(500).send("Data gagal ditambahkan ke database.");
      }
    } catch (error) {
      console.error(
        "Terjadi kesalahan saat menyimpan pemesanan:",
        error.message
      );
      return res.status(500).send("Terjadi kesalahan server: " + error.message);
    }
  }
);

router.get("/penjualan/penawaran", isAuthenticated, async (req, res) => {
  const { status, search, start_date, end_date } = req.query;

  let sql = "SELECT * FROM penjualan_penawaran WHERE 1=1";
  const params = [];

  if (status) {
    sql += " AND status = ?";
    params.push(status);
  }

  if (search) {
    sql += " AND (nomor LIKE ? OR vendor LIKE ?)";
    params.push(`%${search}%`, `%${search}%`);
  }

  if (start_date) {
    sql += " AND tanggal >= ?";
    params.push(start_date);
  }
  if (end_date) {
    sql += " AND tanggal <= ?";
    params.push(end_date);
  }

  sql += " ORDER BY id DESC";

  const [rows] = await db.execute(sql, params);

  res.render("finance/penjualan/penawaran", {
    title: "Penawaran",
    user: req.session.user,
    penawaran: rows,
    status,
    search,
    start_date,
    end_date,
  });
});

router.get("/penjualan/penawaran/create", isAuthenticated, (req, res) => {
  res.render("finance/penjualan/backend/createpenawaran", {
    title: "Buat Penawaran",
    user: req.session.user,
  });
});

router.post(
  "/penjualan/penawaran/create",
  isAuthenticated,
  async (req, res) => {
    try {
      const { nomor, vendor, referensi, tanggal, detail, status, total } =
        req.body;

      if (!nomor || !vendor || !tanggal || !total) {
        return res
          .status(400)
          .send("Data tidak lengkap. Pastikan semua input terisi.");
      }

      const query = `
      INSERT INTO penjualan_penawaran 
      (nomor, vendor, referensi,
     detail, tanggal, status, total)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

      const values = [nomor, vendor, referensi, detail, tanggal, status, total];

      const [result] = await db.execute(query, values);

      if (result.affectedRows > 0) {
        return res.redirect("/penjualan/penawaran");
      } else {
        return res.status(500).send("Data gagal ditambahkan ke database.");
      }
    } catch (error) {
      console.error(
        "Terjadi kesalahan saat menyimpan penawaran:",
        error.message
      );
      return res.status(500).send("Terjadi kesalahan server: " + error.message);
    }
  }
);

router.get("/pembelian", isAuthenticated, (req, res) => {
  res.render("finance/pembelian/overview", {
    title: "Pembelian",
    user: req.session.user,
  });
});

router.get("/pembelian/tagihan", isAuthenticated, async (req, res) => {
  // Ambil query filter
  const { status, search, start_date, end_date } = req.query;

  // Query dasar
  let sql = "SELECT * FROM tagihan WHERE 1=1";
  const params = [];

  // Filter status
  if (status) {
    sql += " AND status = ?";
    params.push(status);
  }

  // Filter search
  if (search) {
    sql += " AND (nomor LIKE ? OR pelanggan LIKE ?)";
    params.push(`%${search}%`, `%${search}%`);
  }

  // Filter tanggal
  if (start_date) {
    sql += " AND tanggal >= ?";
    params.push(start_date);
  }
  if (end_date) {
    sql += " AND tanggal <= ?";
    params.push(end_date);
  }

  sql += " ORDER BY id DESC";

  const [rows] = await db.execute(sql, params);

  res.render("finance/pembelian/tagihan", {
    title: "Tagihan",
    user: req.session.user,
    tagihan: rows,
    status, // <-- kirim status ke EJS
    search, // <-- kirim search ke EJS
    start_date, // <-- kirim start_date ke EJS
    end_date, // <-- kirim end_date ke EJS
  });
});

router.get("/pembelian/tagihan/create", isAuthenticated, (req, res) => {
  res.render("finance/pembelian/backend/createtagihan", {
    title: "Buat Tagihan",
    user: req.session.user,
  });
});

router.post("/pembelian/tagihan/create", isAuthenticated, async (req, res) => {
  try {
    const {
      nomor,
      pelanggan,
      referensi,
      tanggal,
      tgl_jatuh_tempo,
      status,
      sisa_tagihan,
      total,
    } = req.body;

    // Validasi input sederhana
    if (!nomor || !pelanggan || !tanggal || !total) {
      return res
        .status(400)
        .send("Data tidak lengkap. Pastikan semua input terisi.");
    }

    const query = `
      INSERT INTO tagihan 
      (nomor, pelanggan, referensi, tanggal, tgl_jatuh_tempo, status, sisa_tagihan, total)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const values = [
      nomor,
      pelanggan,
      referensi,
      tanggal,
      tgl_jatuh_tempo,
      status,
      sisa_tagihan,
      total,
    ];

    const [result] = await db.execute(query, values);

    if (result.affectedRows > 0) {
      return res.redirect("/pembelian/tagihan");
    } else {
      return res.status(500).send("Data gagal ditambahkan ke database.");
    }
  } catch (error) {
    console.error("Terjadi kesalahan saat menyimpan tagihan:", error.message);
    return res.status(500).send("Terjadi kesalahan server: " + error.message);
  }
});

router.get("/pembelian/pengiriman", isAuthenticated, async (req, res) => {
  // Ambil query filter
  const { status, search, start_date, end_date } = req.query;

  // Query dasar
  let sql = "SELECT * FROM pengiriman WHERE 1=1";
  const params = [];

  // Filter status
  if (status) {
    sql += " AND status = ?";
    params.push(status);
  }

  // Filter search
  if (search) {
    sql += " AND (nomor LIKE ? OR vendor LIKE ?)";
    params.push(`%${search}%`, `%${search}%`);
  }

  // Filter tanggal
  if (start_date) {
    sql += " AND tanggal >= ?";
    params.push(start_date);
  }
  if (end_date) {
    sql += " AND tanggal <= ?";
    params.push(end_date);
  }

  sql += " ORDER BY id DESC";

  const [rows] = await db.execute(sql, params);

  res.render("finance/pembelian/pengiriman", {
    title: "Pengiriman",
    user: req.session.user,
    pengiriman: rows,
    status,
    search,
    start_date,
    end_date,
  });
});

router.post("/pembelian/pengiriman", isAuthenticated, async (req, res) => {
  const { nomor, vendor, detail, referensi, tanggal, status } = req.body;

  // Check for missing fields
  if (!nomor || !vendor || !tanggal) {
    return res.status(400).send("Nomor, vendor, dan tanggal wajib diisi.");
  }

  try {
    const query = `
      INSERT INTO pengiriman 
      (nomor, vendor, detail, referensi, tanggal, status)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    const values = [nomor, vendor, detail, referensi, tanggal, status];

    const [result] = await db.execute(query, values);
    res.redirect("/pembelian/pengiriman");
  } catch (error) {
    console.error("Error saat menyimpan pengiriman:", error.message);
    res.status(500).send("Terjadi kesalahan server.");
  }
});
router.get("/pembelian/pengiriman/create", isAuthenticated, (req, res) => {
  res.render("finance/pembelian/backend/createpengiriman", {
    title: "Tambah Pengiriman",
    user: req.session.user,
  });
});
router.get("/pembelian/pemesanan", isAuthenticated, async (req, res) => {
  const { status, search, start_date, end_date } = req.query;

  let sql = "SELECT * FROM pemesanan WHERE 1=1";
  const params = [];

  if (status) {
    sql += " AND status = ?";
    params.push(status);
  }

  if (search) {
    sql += " AND (nomor LIKE ? OR vendor LIKE ?)";
    params.push(`%${search}%`, `%${search}%`);
  }

  if (start_date) {
    sql += " AND tanggal >= ?";
    params.push(start_date);
  }
  if (end_date) {
    sql += " AND tanggal <= ?";
    params.push(end_date);
  }

  sql += " ORDER BY id DESC";

  const [rows] = await db.execute(sql, params);

  res.render("finance/pembelian/pemesanan", {
    title: "Pemesanan",
    user: req.session.user,
    pemesanan: rows,
    status,
    search,
    start_date,
    end_date,
  });
});

router.get("/pembelian/pemesanan/create", isAuthenticated, (req, res) => {
  res.render("finance/pembelian/backend/createpemesanan", {
    title: "Buat Pemesanan",
    user: req.session.user,
  });
});

router.post(
  "/pembelian/pemesanan/create",
  isAuthenticated,
  async (req, res) => {
    try {
      const {
        nomor,
        vendor,
        referensi,
        tanggal,
        tgl_jatuh_tempo,
        status,
        sisa_tagihan,
        total,
      } = req.body;

      // Validasi input sederhana
      if (!nomor || !vendor || !tanggal || !total) {
        return res
          .status(400)
          .send("Data tidak lengkap. Pastikan semua input terisi.");
      }

      const query = `
      INSERT INTO pemesanan 
      (nomor, vendor, referensi, tanggal, tgl_jatuh_tempo, status, sisa_tagihan, total)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

      const values = [
        nomor,
        vendor,
        referensi,
        tanggal,
        tgl_jatuh_tempo,
        status,
        sisa_tagihan,
        total,
      ];

      const [result] = await db.execute(query, values);

      if (result.affectedRows > 0) {
        return res.redirect("/pembelian/pemesanan");
      } else {
        return res.status(500).send("Data gagal ditambahkan ke database.");
      }
    } catch (error) {
      console.error(
        "Terjadi kesalahan saat menyimpan pemesanan:",
        error.message
      );
      return res.status(500).send("Terjadi kesalahan server: " + error.message);
    }
  }
);

router.get("/pembelian/penawaran", isAuthenticated, async (req, res) => {
  const { status, search, start_date, end_date } = req.query;

  let sql = "SELECT * FROM penawaran WHERE 1=1";
  const params = [];

  if (status) {
    sql += " AND status = ?";
    params.push(status);
  }

  if (search) {
    sql += " AND (nomor LIKE ? OR vendor LIKE ?)";
    params.push(`%${search}%`, `%${search}%`);
  }

  if (start_date) {
    sql += " AND tanggal >= ?";
    params.push(start_date);
  }
  if (end_date) {
    sql += " AND tanggal <= ?";
    params.push(end_date);
  }

  sql += " ORDER BY id DESC";

  const [rows] = await db.execute(sql, params);

  res.render("finance/pembelian/penawaran", {
    title: "Penawaran",
    user: req.session.user,
    penawaran: rows,
    status,
    search,
    start_date,
    end_date,
  });
});

router.get("/pembelian/penawaran/create", isAuthenticated, (req, res) => {
  res.render("finance/pembelian/backend/createpenawaran", {
    title: "Buat Penawaran",
    user: req.session.user,
  });
});

router.post(
  "/pembelian/penawaran/create",
  isAuthenticated,
  async (req, res) => {
    try {
      const { nomor, vendor, referensi, tanggal, detail, status, total } =
        req.body;

      if (!nomor || !vendor || !tanggal || !total) {
        return res
          .status(400)
          .send("Data tidak lengkap. Pastikan semua input terisi.");
      }

      const query = `
      INSERT INTO penawaran 
      (nomor, vendor, referensi,
     detail, tanggal, status, total)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

      const values = [nomor, vendor, referensi, detail, tanggal, status, total];

      const [result] = await db.execute(query, values);

      if (result.affectedRows > 0) {
        return res.redirect("/pembelian/penawaran");
      } else {
        return res.status(500).send("Data gagal ditambahkan ke database.");
      }
    } catch (error) {
      console.error(
        "Terjadi kesalahan saat menyimpan penawaran:",
        error.message
      );
      return res.status(500).send("Terjadi kesalahan server: " + error.message);
    }
  }
);

router.get("/biaya", isAuthenticated, (req, res) => {
  res.render("biaya", { title: "Biaya", user: req.session.user });
});

//inventory routes
router.get("/produk", isAuthenticated, async (req, res) => {
  const [produk] = await db.execute("SELECT * FROM produk ORDER BY id DESC");
  res.render("inventori/table/produk", {
    title: "produk",
    user: req.session.user,
    produk: produk,
  });
});
router.get("/produk/create", isAuthenticated, async (req, res) => {
  const [kategori] = await db.execute(
    "SELECT * FROM kategori_produk ORDER BY id DESC"
  );
  res.render("inventori/backend/createproduk", {
    title: "Tambah Produk",
    user: req.session.user,
    kategori: kategori,
  });
});
router.get("/inventori", isAuthenticated, (req, res) => {
  res.render("inventori/table/inventori", {
    title: "inventori",
    user: req.session.user,
  });
});

router.post(
  "/produk/create",
  isAuthenticated,
  upload.single("gambar"),
  async (req, res) => {
    let {
      nama_produk,
      kategori,
      harga_jual,
      harga_beli,
      deskripsi,
      kode_sku,
      satuan,
    } = req.body;
    const gambar = req.file ? req.file.filename : null;

    // Ganti undefined menjadi null jika ada
    nama_produk = nama_produk || null;
    kategori = kategori || null;
    harga_jual = harga_jual || null;
    harga_beli = harga_beli || null;
    deskripsi = deskripsi || null;
    kode_sku = kode_sku || null;
    satuan = satuan || null;

    try {
      await db.execute(
        "INSERT INTO produk (nama_produk, id_kategori, gambar, harga_jual, harga_beli, deskripsi, kode_sku, satuan) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
          nama_produk,
          kategori,
          gambar,
          harga_jual,
          harga_beli,
          deskripsi,
          kode_sku,
          satuan,
        ]
      );
      res.redirect("/produk");
    } catch (err) {
      console.error("❌ Error simpan produk:", err);
      res.status(500).send("Gagal menyimpan produk. Cek log server.");
    }
  }
);

router.post("/kategori/create", isAuthenticated, async (req, res) => {
  const { nama_kategori } = req.body;
  if (!nama_kategori)
    return res.status(400).json({ error: "Nama kategori wajib diisi" });

  // Simpan ke tabel kategori_produk
  const [result] = await db.execute(
    "INSERT INTO kategori_produk (nama_kategori) VALUES (?)",
    [nama_kategori]
  );
  // Kirim id kategori baru ke frontend
  res.json({ id: result.insertId, nama_kategori });
});

router.get("/laporan", isAuthenticated, (req, res) => {
  res.render("laporan", { title: "laporan", user: req.session.user });
});
router.get("/kas-bank", isAuthenticated, (req, res) => {
  res.render("kas-bank", { title: "kas-bank", user: req.session.user });
});

module.exports = router;
