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
    cb(null, path.join(__dirname, "../public/uploads"));
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
      telephone: user.telephone, // Tambahkan telepon jika ada
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
// Route to list clients
router.get('/clients', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Forbidden');
  }

  const userId = req.session.user.id;

  // Fetch only the clients created by the logged-in user
  const [rows] = await db.execute(`
    SELECT clients.*, users.name AS creator_name
    FROM clients
    LEFT JOIN users ON clients.created_by = users.id
    WHERE clients.created_by = ?
    ORDER BY clients.id DESC
  `, [userId]);

  res.render('crm/table/klien', { title: 'Daftar Klien', user: req.session.user, clients: rows });
});

// Route to create a new client (client creation form)
router.get('/crm/backend/createklien', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Forbidden');
  }

  // No changes here, just show the client creation page
  res.render('crm/backend/createklien', { title: 'Tambah Klien', user: req.session.user });
});

// Route to add a new client
router.post('/clients', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Forbidden');
  }

  const { nama_klien: name, perusahaan_klien: company, nomor_telpon_klien: phone, email_klien: email } = req.body;
  const userId = req.session.user.id;

  await db.execute('INSERT INTO clients (name, company, phone, email, created_by) VALUES (?, ?, ?, ?, ?)', [name, company, phone, email, userId]);
  res.redirect('/clients');
});

// Route to edit a client (client edit form)
router.get('/clients/edit/:id', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Forbidden');
  }

  const userId = req.session.user.id;
  const clientId = req.params.id;

  // Check if the client belongs to the logged-in user
  const [rows] = await db.execute('SELECT * FROM clients WHERE id = ? AND created_by = ?', [clientId, userId]);

  if (rows.length === 0) {
    return res.status(404).send('Client not found or you do not have permission to edit this client');
  }

  res.render('crm/backend/editklien', { title: 'Edit Klien', user: req.session.user, client: rows[0] });
});

// Route to update client data
router.post('/clients/edit/:id', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Forbidden');
  }

  const { nama_klien, perusahaan_klien, nomor_telpon_klien, email_klien } = req.body;
  const userId = req.session.user.id;
  const clientId = req.params.id;

  // Update client data if it belongs to the logged-in user
  await db.execute('UPDATE clients SET name = ?, company = ?, phone = ?, email = ? WHERE id = ? AND created_by = ?', [nama_klien, perusahaan_klien, nomor_telpon_klien, email_klien, clientId, userId]);
  res.redirect('/clients');
});

// Route to delete a client
router.post('/clients/delete/:id', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
    return res.status(403).send('Forbidden');
  }

  const userId = req.session.user.id;
  const clientId = req.params.id;

  // Check if the client belongs to the logged-in user before deleting
  await db.execute('DELETE FROM clients WHERE id = ? AND created_by = ?', [clientId, userId]);
  res.redirect('/clients');
});

// =========================================================================================================

// Route to list interactions
// router.get("/interactions", isAuthenticated, async (req, res) => {
//   const { search, sortBy, order } = req.query; // Ambil parameter pencarian dan pengurutan

//   // Default sort jika tidak ada yang diberikan
//   const sortColumn = sortBy || 'created_at'; // Kolom yang digunakan untuk pengurutan
//   const sortOrder = order === 'desc' ? 'DESC' : 'ASC'; // Urutan pengurutan (asc/desc)

//   let sql = "SELECT * FROM interactions WHERE 1=1"; // Query dasar
//   const params = [];
//   const userRole = req.session.user.role;

//   // Filter interaksi berdasarkan peran (sales, admin-sales, admin)
//   if (userRole === 'sales') {
//     sql += " AND created_by = ?"; // Sales hanya bisa melihat interaksi yang mereka buat
//     params.push(req.session.user.id);
//   } else if (userRole === 'admin-sales' || userRole === 'admin') {
//     // Admin-sales dan admin bisa melihat semua data, jadi tidak ada filter khusus
//     // Bisa tambahkan filter lain jika perlu
//   }

//   // Jika ada kata kunci pencarian, cari di semua kolom
//   if (search) {
//     sql += " AND (client_name LIKE ? OR type LIKE ? OR notes LIKE ?)";
//     params.push(`%${search}%`, `%${search}%`, `%${search}%`);
//   }

//   // Terapkan pengurutan
//   sql += ` ORDER BY ${sortColumn} ${sortOrder}`;

//   // Eksekusi query
//   const [rows] = await db.execute(sql, params);
//   res.render('crm/table/interaksi', {
//     title: 'Daftar Interaksi',
//     user: req.session.user,
//     interactions: rows,
//     search,
//     sortBy,
//     order
//   });
// });


// // Route to add a new interaction
// router.get('/interactions/tambah', isAuthenticated, async (req, res) => {
//   if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
//     return res.status(403).send('Forbidden');
//   }

//   const userId = req.session.user.id;
//   const [clients] = await db.execute('SELECT id, name FROM clients WHERE created_by = ?', [userId]);
//   res.render('crm/backend/createinteraksiklien', { title: 'Tambah Interaksi', user: req.session.user, clients });
// });

// // Route to save a new interaction
// router.post('/interactions', isAuthenticated, upload.single('attachment'), async (req, res) => {
//   if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
//     return res.status(403).send('Forbidden');
//   }

//   const { client_id, type, notes, send_email, subjek } = req.body;
//   const userId = req.session.user.id;
//   const file = req.file;

//   // Insert the new interaction
//   await db.execute(`
//     INSERT INTO interactions (user_id, client_id, type, subjek, notes, file_path, send_email, created_by)
//     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
//   `, [userId, client_id, type, subjek, notes, file?.path || null, send_email ? 1 : 0, userId]);

//   // If email is to be sent, send it
//   if (send_email) {
//     const [client] = await db.execute('SELECT email FROM clients WHERE id = ?', [client_id]);
//     const email = client[0]?.email;

//     if (email) {
//       const [emailConfig] = await db.execute('SELECT * FROM konfig_email LIMIT 1');
//       const { type, host, port, username, password } = emailConfig[0];

//       const transporter = nodemailer.createTransport({
//         service: type === 'gmail' ? 'gmail' : undefined,
//         host: type === 'smtp' ? host : undefined,
//         port: type === 'smtp' ? port : undefined,
//         auth: {
//           user: username,
//           pass: password
//         }
//       });

//       const mailOptions = {
//         from: 'noreply',
//         to: email,
//         subject: subjek,
//         text: notes,
//         attachments: file ? [{
//           filename: file.originalname,
//           path: file.path
//         }] : []
//       };

//       await transporter.sendMail(mailOptions);
//     }
//   }

//   res.redirect('/interactions');
// });

// KONFIGURASI EMAIL 


router.get('/email', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
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

// Routes untuk menampilkan daftar aktivitas
router.get('/activity', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Dilarang');
  }

  const search = req.query.search || '';
  const sortBy = req.query.sortBy || 'created_at';
  const order = req.query.order || 'desc';

  const [activities] = await db.execute(
    `SELECT activities.*,
    plans.id as plan_id, plans.tanggal_fu, plans.tipe_fu, plans.hasil_fu, plans.hasil_akhir
    FROM activities
    LEFT JOIN plans ON activities.id = plans.id_activity
    WHERE no_activity LIKE ? 
    ORDER BY ${sortBy} ${order}`,
    [`%${search}%`]
  );

  res.render('crm/table/activity', {
    title: 'Daftar Aktivitas',
    user: req.session.user,
    activities,
    search,
    sortBy,
    order
  });
});

router.get('/activity/:id', isAuthenticated, async (req, res) => {
  const activityId = req.params.id;
  const user = req.session.user;
  const search = req.query.search || '';
  const sortBy = req.query.sortBy || 'created_at';
  const order = req.query.order || 'desc';

  if (user.role !== 'admin' && user.role !== 'sales' && user.role !== 'admin-sales') {
    return res.status(403).send('Dilarang');
  }
  try {
    const [activity] = await db.execute(
      `SELECT activities.*, plans.file_fu, plans.tanggal_fu, plans.tipe_fu, plans.hasil_fu, plans.hasil_akhir, plans.file_akhir
      FROM activities
      LEFT JOIN plans ON activities.id = plans.id_activity
      WHERE activities.id = ?`,
      [activityId]
    );

    if (activity.length > 0) {
      res.render('crm/table/detailactivity', {
        activity: activity[0],
        user
      });
    } else {
      res.status(404).send('Activity tidak ditemukan');
    }
  } catch (err) {
    console.error('Error fetching activity:', err);
    res.status(500).send('Terjadi kesalahan saat mengambil data activity');
  }
});


// Routes untuk menampilkan form tambah aktivitas
router.get('/create-activity', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Dilarang');
  }

  // Ambil data klien dari database
  const [clients] = await db.execute('SELECT * FROM clients');

  // Menghitung jumlah aktivitas untuk tahun ini
  const currentYear = new Date().getFullYear();
  const [activityCount] = await db.execute('SELECT COUNT(*) AS count FROM activities WHERE YEAR(created_at) = ?', [currentYear]);

  // Menentukan nomor aktivitas berdasarkan jumlah aktivitas di tahun ini
  const no_activity = `ka/${activityCount[0].count + 1}/${currentYear}`;

  // Kirimkan variabel no_activity ke EJS
  res.render('crm/backend/create-activity', {
    title: 'Buat Aktivitas',
    user: req.session.user,
    clients: clients, // pastikan clients ada
    no_activity // pastikan no_activity dikirimkan ke EJS
  });
});

// Routes untuk menyimpan data aktivitas yang baru dibuat
router.post('/create-activity/add', isAuthenticated, async (req, res) => {
  const { name_perusahaan, jenis_perusahaan, source_of_business, pic_name, pic_telephone, pic_position } = req.body;
  const currentYear = new Date().getFullYear();

  // Hitung no_activity berdasarkan tahun dan jumlah aktivitas yang ada
  const [activityCount] = await db.execute('SELECT COUNT(*) AS count FROM activities WHERE YEAR(created_at) = ?', [currentYear]);
  const no_activity = `ka/${activityCount[0].count + 1}/${currentYear}`;

  // Log data yang diterima untuk debugging
  console.log(req.body);  // Log untuk memeriksa data yang diterima

  try {
    // Simpan data ke dalam database
    await db.execute('INSERT INTO activities (name_perusahaan, jenis_perusahaan, source_of_business, pic_name, pic_telephone, pic_position, no_activity, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())',
      [name_perusahaan, jenis_perusahaan, source_of_business, pic_name, pic_telephone, pic_position, no_activity]);

    // Arahkan ke halaman daftar aktivitas setelah berhasil
    res.redirect('/activity');
  } catch (err) {
    console.error(err);  // Log kesalahan
    res.render('crm/backend/create-activity', { no_activity, error: 'Terjadi kesalahan server', title: 'Buat Aktivitas', user: req.session.user, clients: [] });
  }
});

// Route untuk menampilkan form create plan dan memilih activity
router.get('/create-plan', isAuthenticated, async (req, res) => {
  // Ambil data semua activities
  const [activities] = await db.execute('SELECT * FROM activities');

  // Render form create plan
  res.render('crm/backend/create-plans', {
    title: 'Create Plan',
    user: req.session.user, // Tambahkan user ke dalam variabel yang akan dikirimkan ke EJS
    activities: activities
  });
});

// POST: Menyimpan Plan Baru
router.post('/plans', isAuthenticated, async (req, res) => {
  const { tanggal_fu, tipe_fu, id_activity } = req.body;

  try {
    // Menyimpan data plan yang baru ke dalam tabel plans
    await db.execute(
      'INSERT INTO plans (tanggal_fu, tipe_fu, id_activity) VALUES (?, ?, ?)',
      [tanggal_fu, tipe_fu, id_activity]
    );

    // Redirect ke halaman detail activity setelah plan berhasil ditambahkan
    res.redirect(`/activity/${id_activity}`);
  } catch (err) {
    console.error('Error adding plan:', err);
    res.status(500).send('Terjadi kesalahan saat menyimpan rencana.');
  }
});

router.post('/plans/hasil-fu', upload.single('file_upload'), isAuthenticated, async (req, res) => {
  const { plan_id, hasil_fu, id_activity } = req.body;
  const file = req.file;

  try {
    // Log to check what data is received
    console.log('Received data for Hasil FU:', { plan_id, hasil_fu, id_activity, file });
    console.log('Received plan_id:', plan_id);  // Log plan_id

    // Define file path and file name
    const fileName = file ? file.filename : null;
    const filePath = file ? '/uploads/' + file.filename : null;

    // Log to check file path
    console.log('File info:', { fileName, filePath });

    // Ensure plan_id is correct and an integer
    const planId = parseInt(plan_id, 10);

    // Log before executing the SQL query
    console.log('Executing SQL query to update plan_id:', planId);

    // Update the database
    const [result] = await db.execute(
      `UPDATE plans SET hasil_fu = ?, file_fu = ? WHERE id = ?`,
      [hasil_fu, filePath, planId]
    );

    // Log to see the result of the SQL query
    console.log('Database update result:', result);

    // Check if the update affected any rows
    if (result.affectedRows > 0) {
      res.redirect(`/activity/${id_activity}`);
    } else {
      // No rows updated, log and return error
      console.error('No rows affected in database update');
      res.status(500).send('Tidak ada data yang diperbarui di database.');
    }
  } catch (err) {
    // Log error
    console.error('Error updating FU result and file:', err);
    res.status(500).send('Terjadi kesalahan saat memperbarui hasil FU dan file.');
  }
});


router.post('/plans/hasil-akhir', upload.single('file_upload'), isAuthenticated, async (req, res) => {
  const { plan_id, hasil_akhir, id_activity } = req.body;
  const file = req.file;

  try {
    // Log untuk memastikan data yang diterima
    console.log('Received data for Hasil Akhir:', { plan_id, hasil_akhir, id_activity, file });

    // Menentukan nama dan path file
    const fileName = file ? file.filename : null;
    const filePath = file ? '/uploads/' + file.filename : null;

    // Log untuk mengecek path file yang akan disimpan
    console.log('File info:', { fileName, filePath });

    // Update database
    const [result] = await db.execute(
      `UPDATE plans SET hasil_akhir = ?, file_akhir = ? WHERE id = ?`,
      [hasil_akhir, filePath, plan_id]
    );

    // Log untuk memeriksa hasil dari query database
    console.log('Database update result:', result);

    if (result.affectedRows > 0) {
      // Jika ada data yang diperbarui, redirect ke halaman activity
      res.redirect(`/activity/${id_activity}`);
    } else {
      // Jika tidak ada data yang diperbarui, tampilkan pesan error
      console.error('No rows affected in database update');
      res.status(500).send('Tidak ada data yang diperbarui di database.');
    }
  } catch (err) {
    // Log error yang terjadi
    console.error('Error updating Akhir result and file:', err);
    res.status(500).send('Terjadi kesalahan saat memperbarui hasil Akhir dan file.');
  }
});


router.get("/po-management", isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Dilarang');
  }

  const search = req.query.search || '';
  const [poList] = await db.execute(
    "SELECT * FROM po WHERE po_number LIKE ? ORDER BY created_at DESC",
    [`%${search}%`]
  );

  res.render("crm/table/po-management", {
    title: "Pengelolaan PO",
    user: req.session.user,
    poList,
    search
  });
});

router.get("/create-po", isAuthenticated, async (req, res) => {
  try {
    // Ambil semua data client
    const [clients] = await db.execute("SELECT * FROM clients");

    // Ambil informasi user dan role dari session
    const { name: pic_name, role, telephone: pic_phone } = req.session.user;

    // Tentukan pic_position berdasarkan role
    let pic_position = '';
    if (role === 'admin') {
      pic_position = 'Administrator';
    } else if (role === 'sales') {
      pic_position = 'Sales Representative';
    } else if (role === 'admin-sales') {
      pic_position = 'Sales Manager';
    } else {
      pic_position = 'Unknown';
    }

    // Kirim data client dan PIC ke tampilan
    res.render("crm/backend/create-po", {
      title: "Buat PO Baru",
      user: req.session.user,
      pic_name,
      pic_position,
      pic_phone,
      clients, // Kirim data client ke tampilan
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Terjadi kesalahan saat mengambil data client");
  }
});



router.post("/create-po", isAuthenticated, async (req, res) => {
  const { po_details, client_id, value } = req.body;
  const { name: pic_name, role, telephone: pic_phone } = req.session.user;

  // Tentukan pic_position berdasarkan role
  let pic_position = '';
  if (role === 'admin') {
    pic_position = 'Administrator';
  } else if (role === 'sales') {
    pic_position = 'Sales Representative';
    } else if (role === 'admin-sales') {
      pic_position = 'Sales Manager';
  } else {
    pic_position = 'Unknown'; // Atur default jika role tidak ditemukan
  }

  // Cek jika client_id, po_details, dan value ada dan tidak undefined
  if (!client_id || !po_details || !value) {
    return res.status(400).send("Semua field harus diisi.");
  }

  try {
    // Ambil data client berdasarkan ID
    const [client] = await db.execute("SELECT * FROM clients WHERE id = ?", [client_id]);

    if (client.length === 0) {
      return res.status(404).send("Client tidak ditemukan");
    }

    const client_name = client[0].name;
    const client_company = client[0].company;
    const client_phone = client[0].phone;
    const client_email = client[0].email;

    // Auto-generate nomor PO
    const po_number = `PO-${Date.now()}`;

    // Simpan PO ke database
    await db.execute(
      "INSERT INTO po (po_number, po_details, created_by, pic_name, pic_position, pic_phone, client_name, client_company, client_phone, client_email, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [po_number, po_details, req.session.user.id, pic_name, pic_position, pic_phone, client_name, client_company, client_phone, client_email, value]
    );

    // Kirim notifikasi email jika diperlukan
    const [emailConfig] = await db.execute("SELECT * FROM konfig_email LIMIT 1");
    const { type, host, port, username, password } = emailConfig[0];

    if (type && host && port && username && password) {
      const transporter = nodemailer.createTransport({
        service: type === "gmail" ? "gmail" : undefined,
        host: type === "smtp" ? host : undefined,
        port: type === "smtp" ? port : undefined,
        auth: {
          user: username,
          pass: password
        }
      });

      const mailOptions = {
        from: "noreply@example.com",
        to: req.session.user.email,  // Kirim ke email pengguna
        subject: `Notifikasi Pembuatan PO: ${po_number}`,
        text: `PO baru telah dibuat dengan nomor PO: ${po_number}, rincian sebagai berikut:\n\n${po_details}\n\nPIC: ${pic_name}\nJabatan: ${pic_position}\nNomor PIC: ${pic_phone}\n\nClient: ${client_name}\nPerusahaan Client: ${client_company}\nNomor Telepon Client: ${client_phone}\nEmail Client: ${client_email}`
      };

      await transporter.sendMail(mailOptions);
    }

    res.redirect("/po-management");
  } catch (err) {
    console.error("Error saat membuat PO:", err);
    res.status(500).send("Terjadi kesalahan saat membuat PO");
  }
});



router.get("/po-detail/:id", isAuthenticated, async (req, res) => {
   if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Dilarang');
  }
  const poId = req.params.id;

  // Ambil detail PO
  const [poDetail] = await db.execute("SELECT * FROM po WHERE id = ?", [poId]);

  if (poDetail.length === 0) {
    return res.status(404).send("PO tidak ditemukan");
  }

  res.render("crm/table/po-detail", {
    title: "Detail PO",
    po: poDetail[0],
    user: req.session.user
  });
});

router.get("/client-info/:id", async (req, res) => {
  const clientId = req.params.id;

  try {
    const [client] = await db.execute("SELECT * FROM clients WHERE id = ?", [clientId]);
    if (client.length === 0) {
      return res.status(404).send("Client tidak ditemukan");
    }

    // Kirimkan data client sebagai JSON
    res.json({
      client_name: client[0].name,
      client_company: client[0].company,
      client_phone: client[0].phone,
      client_email: client[0].email,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Terjadi kesalahan saat mengambil data client");
  }
});


router.post("/approve-po/:id", isAuthenticated, async (req, res) => {
  const poId = req.params.id;
  const userId = req.session.user.id;
  const action = req.body.action; // 'approve' or 'cancel'

  if (action !== "approve" && action !== "cancel") {
    return res.status(400).send("Aksi tidak valid");
  }

  try {
    if (action === "approve") {
      // Update PO menjadi approved dan set tanggal approve
      await db.execute(
        "UPDATE po SET po_status = 'approved', approved_by = ?, approved_at = NOW() WHERE id = ?",
        [userId, poId]
      );
    } else if (action === "cancel") {
      // Update PO menjadi cancelled
      await db.execute(
        "UPDATE po SET po_status = 'cancelled' WHERE id = ?",
        [poId]
      );
    }

    res.redirect("/po-management");
  } catch (err) {
    console.error(err);
    res.status(500).send("Terjadi kesalahan saat mengubah status PO");
  }
});

router.post("/revised-po/:id", isAuthenticated, async (req, res) => {
  const poId = req.params.id;
  const { po_details } = req.body;

  try {
    // Update PO dengan rincian yang baru dan tanggal revisi
    await db.execute(
      "UPDATE po SET po_details = ?, revised_at = NOW() WHERE id = ?",
      [po_details, poId]
    );

    res.redirect(`/po-detail/${poId}`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Terjadi kesalahan saat merevisi PO");
  }
});


router.get('/interactions', isAuthenticated, async (req, res) => {
  const [rows] = await db.execute('SELECT * FROM interactions');
  res.render('crm/table/interaksi', { title: 'Interaksi', user: req.session.user, interactions: rows });
});

router.post('/add-interaction', isAuthenticated, async (req, res) => {
  const { client_id, interaction_type, interaction_date, notes } = req.body;
  await db.execute('INSERT INTO interactions (client_id, interaction_type, interaction_date, notes) VALUES (?, ?, ?, ?)', [client_id, interaction_type, interaction_date, notes]);

  res.redirect('/interactions');
});


// =========================================================================================================

// Rute untuk klien
router.get("/admin-sales/clients", isAuthenticated, async (req, res) => {
  const { search, sortBy, order } = req.query;
  const sortColumn = sortBy || 'created_at';
  const sortOrder = order === 'desc' ? 'DESC' : 'ASC';
  let sql = "SELECT * FROM clients WHERE 1=1";
  const params = [];
  const userRole = req.session.user.role;

  if (userRole === 'sales') {
    sql += " AND created_by = ?"; // Sales hanya bisa melihat klien yang mereka buat
    params.push(req.session.user.id);
  }

  if (search) {
    sql += " AND (name LIKE ? OR company LIKE ? OR email LIKE ?)";
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  sql += ` ORDER BY ${sortColumn} ${sortOrder}`;

  const [rows] = await db.execute(sql, params);
  res.render('crm/table/klien', {
    title: 'Tabel Klien',
    user: req.session.user,
    clients: rows,
    search,
    sortBy,
    order
  });
});

// Rute untuk detailKlien
router.get("/admin-sales/clients/detail/:userId", isAuthenticated, async (req, res) => {
  const userId = req.params.userId;
  const [user] = await db.execute('SELECT id, name FROM users WHERE id = ?', [userId]);

  if (!user.length) {
    return res.status(404).send('User not found');
  }

  const [clients] = await db.execute(`
    SELECT clients.id, clients.name AS client_name, clients.company, clients.email, clients.phone, users.name AS creator_name
    FROM clients
    LEFT JOIN users ON clients.created_by = users.id
    WHERE clients.created_by = ?
    ORDER BY clients.id DESC`, [userId]);

  res.render('crm/table/detailKlien', {
    user: req.session.user,
    selectedUser: user[0],
    clients
  });
});


// Route to add a new client
router.post('/admin-sales/clients', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Forbidden');
  }

  const { nama_klien: name, perusahaan_klien: company, nomor_telpon_klien: phone, email_klien: email } = req.body;

  await db.execute('INSERT INTO clients (name, company, phone, email) VALUES (?, ?, ?, ?)', [name, company, phone, email]);
  res.redirect('/admin-sales/clients');
});

// Route to edit a client (client edit form)
router.get('/admin-sales/clients/edit/:id', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Forbidden');
  }

  const clientId = req.params.id;

  const [rows] = await db.execute('SELECT * FROM clients WHERE id = ?', [clientId]);

  if (rows.length === 0) {
    return res.status(404).send('Client not found');
  }

  res.render('crm/backend/editklien', { title: 'Edit Klien', user: req.session.user, client: rows[0] });
});

// Route to update client data
router.post('/admin-sales/clients/edit/:id', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Forbidden');
  }

  const { nama_klien, perusahaan_klien, nomor_telpon_klien, email_klien } = req.body;
  const clientId = req.params.id;

  await db.execute('UPDATE clients SET name = ?, company = ?, phone = ?, email = ? WHERE id = ?', [nama_klien, perusahaan_klien, nomor_telpon_klien, email_klien, clientId]);
  res.redirect('/admin-sales/clients');
});

// Route to delete a client
router.post('/admin-sales/clients/delete/:id', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'sales') {
    return res.status(403).send('Forbidden');
  }

  const clientId = req.params.id;

  await db.execute('DELETE FROM clients WHERE id = ?', [clientId]);
  res.redirect('/admin-sales/clients');
});


// Rute untuk adminInteraksi
router.get("/admin-sales/interactions", isAuthenticated, async (req, res) => {
  const { search, sortBy, order } = req.query;
  const sortColumn = sortBy || 'created_at';
  const sortOrder = order === 'desc' ? 'DESC' : 'ASC';
  let sql = "SELECT * FROM interactions WHERE 1=1";
  const params = [];
  const userRole = req.session.user.role;

  if (userRole === 'sales') {
    sql += " AND created_by = ?"; // Sales hanya melihat interaksi yang mereka buat
    params.push(req.session.user.id);
  }

  if (search) {
    sql += " AND (client_name LIKE ? OR type LIKE ? OR notes LIKE ? OR created_by_name LIKE ?)";
    params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
  }

  sql += ` ORDER BY ${sortColumn} ${sortOrder}`;

  const [rows] = await db.execute(sql, params);
  const [salesUsers] = await db.execute('SELECT id, name FROM users WHERE role = ?', ['sales']);

  res.render('crm/table/adminInteraksi', {
    title: 'Tabel Interaksi Sales',
    user: req.session.user,
    interactions: rows,
    search,
    salesUsers
  });
});


// Rute untuk detailInteraksi
router.get("/admin-sales/interactions/detail/:userId", isAuthenticated, async (req, res) => {
  const userId = req.params.userId;
  const { search, sortBy, order } = req.query; // Ambil parameter pencarian dan pengurutan
  const sortColumn = sortBy || 'interactions.created_at'; // Gunakan alias tabel untuk created_at
  const sortOrder = order === 'desc' ? 'DESC' : 'ASC';

  const [user] = await db.execute('SELECT id, name FROM users WHERE id = ?', [userId]);

  if (!user.length) {
    return res.status(404).send('User not found');
  }

  let sql = `
    SELECT interactions.type, interactions.notes, clients.name AS client_name
    FROM interactions
    JOIN clients ON interactions.client_id = clients.id
    WHERE interactions.created_by = ?`;

  const params = [userId];

  if (search) {
    sql += " AND (clients.name LIKE ? OR interactions.type LIKE ? OR interactions.notes LIKE ?)";
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  // Menambahkan pengurutan berdasarkan kolom yang diberikan
  sql += ` ORDER BY ${sortColumn} ${sortOrder}`;

  const [interactions] = await db.execute(sql, params);

  res.render('crm/table/detailInteraksi', {
    sales: user[0],
    user: req.session.user,
    interactions,
    search,
    sortBy,
    order
  });
});

router.get('/admin-sales/interactions/detail/:interactionId', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Forbidden');
  }

  const interactionId = req.params.interactionId;

  // Ambil data interaksi berdasarkan ID
  const [interaction] = await db.execute(`
    SELECT interactions.*, clients.name AS client_name, users.name AS created_by_name
    FROM interactions
    JOIN clients ON interactions.client_id = clients.id
    JOIN users ON interactions.created_by = users.id
    WHERE interactions.id = ?
  `, [interactionId]);

  if (interaction.length === 0) {
    return res.status(404).send('Interaksi tidak ditemukan');
  }

  res.json(interaction[0]);
});



// Admin-Sales: Tambah Interaksi
router.get('/admin-sales/interactions/tambah', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'admin-sales') {
    return res.status(403).send('Forbidden');
  }

  const [clients] = await db.execute('SELECT id, name FROM clients');
  res.render('crm/backend/createinteraksiklien', { title: 'Daftar Interaksi', user: req.session.user, clients });
});

// Admin-Sales: Proses Tambah Interaksi
router.post('/admin-sales/interactions', isAuthenticated, upload.single('attachment'), async (req, res) => {
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

  res.redirect('/admin-sales/interactions');
});

// Admin-Sales: Konfigurasi Email
router.get('/admin-sales/email', isAuthenticated, async (req, res) => {
  if (req.session.user.role !== 'admin-sales') {
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

// Admin-Sales: Proses Konfigurasi Email
router.post('/admin-sales/prosesemail', isAuthenticated, async (req, res) => {
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

  res.redirect('/admin-sales/email');
});


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

router.get('/produk', isAuthenticated, async (req, res) => {
  const [produk] = await db.execute(`
    SELECT produk.*, kategori.nama_kategori, gudang.nama_gudang 
    FROM produk 
    LEFT JOIN kategori ON produk.id_kategori = kategori.id 
    LEFT JOIN gudang ON produk.id_gudang = gudang.id
  `);
  res.render('inventori/table/produk', { produk, title: "Produk", user: req.session.user });
});

// Form tambah
router.get('/produk/create', isAuthenticated, async (req, res) => {
  const [kategori] = await db.execute('SELECT * FROM kategori');
  const [gudang] = await db.execute('SELECT * FROM gudang');
  res.render('inventori/backend/createproduk', { kategori, gudang, title: "Tambah Produk", user: req.session.user });
});

// Simpan produk baru
router.post('/produk/create', isAuthenticated, upload.single('gambar'), async (req, res) => {
  const {
    id_kategori,
    id_gudang,
    nama_produk,
    harga_beli,
    harga_jual,
    satuan,
    kode_sku,
    serial_number,
    deskripsi
  } = req.body;

  // Ambil nama file gambar hasil upload
  const gambar = req.file ? req.file.filename : null;

  await db.execute(
    `INSERT INTO produk 
      (id_kategori, id_gudang, nama_produk, gambar, harga_beli, harga_jual, satuan, kode_sku, serial_number, deskripsi)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id_kategori, id_gudang, nama_produk, gambar, harga_beli, harga_jual, satuan, kode_sku, serial_number, deskripsi]
  );
  res.redirect('/produk');
});

// Update
router.post('/produk/update/:id', isAuthenticated, upload.single('gambar'), async (req, res) => {
  const {
    id_kategori,
    id_gudang,
    nama_produk,
    harga_beli,
    harga_jual,
    satuan,
    kode_sku,
    serial_number,
    deskripsi
  } = req.body;

  const gambar = req.file ? req.file.filename : null;

  const query = gambar
    ? `UPDATE produk SET id_kategori=?, id_gudang=?, nama_produk=?, gambar=?, harga_beli=?, harga_jual=?, satuan=?, kode_sku=?, serial_number=?, deskripsi=? WHERE id=?`
    : `UPDATE produk SET id_kategori=?, id_gudang=?, nama_produk=?, harga_beli=?, harga_jual=?, satuan=?, kode_sku=?, serial_number=?, deskripsi=? WHERE id=?`;

  const params = gambar
    ? [id_kategori, id_gudang, nama_produk, gambar, harga_beli, harga_jual, satuan, kode_sku, serial_number, deskripsi, req.params.id]
    : [id_kategori, id_gudang, nama_produk, harga_beli, harga_jual, satuan, kode_sku, serial_number, deskripsi, req.params.id];

  await db.execute(query, params);
  res.redirect('/produk');
});

// Hapus
router.get('/produk/delete/:id', isAuthenticated, async (req, res) => {
  await db.execute('DELETE FROM produk WHERE id = ?', [req.params.id]);
  res.redirect('/produk');
});

// Tambah kategori dari modal AJAX
router.post('/kategori/create', isAuthenticated, async (req, res) => {
  const { nama_kategori } = req.body;
  const [result] = await db.execute('INSERT INTO kategori (nama_kategori) VALUES (?)', [nama_kategori]);
  res.json({ id: result.insertId, nama_kategori });
});

router.get('/gudang', isAuthenticated, async (req, res) => {
  const [gudangs] = await db.execute('SELECT * FROM gudang ORDER BY id DESC');
  res.render('inventori/table/inventori', { title: 'Inventori', user: req.session.user, gudangs });
});

router.get('/gudang/create', isAuthenticated, async (req, res) => {
  const [gudangs] = await db.execute('SELECT * FROM gudang ORDER BY id DESC');
  res.render('inventori/backend/creategudang', { title: 'Inventori', user: req.session.user, gudangs });
});

// POST: Tambah gudang
router.post('/gudang/create', isAuthenticated, async (req, res) => {
  const { nama_gudang, lokasi, kode } = req.body;
  await db.execute('INSERT INTO gudang (nama_gudang, lokasi, kode) VALUES (?, ?, ?)', [nama_gudang, lokasi, kode]);
  res.redirect('/gudang');
});

// POST: Update gudang
router.post('/gudang/update/:id', isAuthenticated, async (req, res) => {
  const { id } = req.params;
  const { nama_gudang, lokasi, kode } = req.body;
  await db.execute('UPDATE gudang SET nama_gudang = ?, lokasi = ?, kode = ? WHERE id = ?', [nama_gudang, lokasi, kode, id]);
  res.redirect('/gudang');
});

// GET: Hapus gudang
router.get('/gudang/delete/:id', isAuthenticated, async (req, res) => {
  const { id } = req.params;
  await db.execute('DELETE FROM gudang WHERE id = ?', [id]);
  res.redirect('/gudang');
});

// GET: Semua transaksi
router.get('/transaksi', isAuthenticated, async (req, res) => {
  const [rows] = await db.execute(`
    SELECT t.*, g.nama_gudang, COUNT(td.id) AS total_produk
    FROM transaksi t
    JOIN gudang g ON t.gudang_id = g.id
    LEFT JOIN transaksi_detail td ON td.transaksi_id = t.id
    GROUP BY t.id
    ORDER BY t.tanggal DESC
  `);

  res.render('inventori/table/transaksi', {
    title: 'Transaksi Stok',
    transaksi: rows,
    user: req.session.user
  });
});

// GET: Form tambah transaksi
router.get('/transaksi/create', isAuthenticated, async (req, res) => {
  const [produk] = await db.execute('SELECT * FROM produk');
  const [gudang] = await db.execute('SELECT * FROM gudang');

  res.render('inventori/backend/createTransaksi', {
    title: 'Tambah Transaksi',
    produk,
    gudang,
    user: req.session.user
  });
});



router.post('/transaksi/create', isAuthenticated, async (req, res) => {
  let {
    nomor,
    tipe,
    gudang_id,
    tanggal,
    referensi,
    produk_id, // Array input produk
    qty,       // Array input qty
    harga      // Array input harga
  } = req.body;

  // Pastikan produk_id, qty, dan harga adalah array, bahkan jika hanya ada satu elemen
  if (!Array.isArray(produk_id)) {
    produk_id = produk_id ? [produk_id] : [];
  }
  if (!Array.isArray(qty)) {
    qty = qty ? [qty] : [];
  }
  if (!Array.isArray(harga)) {
    harga = harga ? [harga] : [];
  }

  // Log untuk memeriksa data yang diterima
  console.log('Produk ID:', produk_id);
  console.log('Qty:', qty);
  console.log('Harga:', harga);

  // Validasi input utama
  if (!nomor || !tipe || !gudang_id || !tanggal) {
    return res.status(400).send('Data utama tidak boleh kosong.');
  }

  // Menyimpan transaksi utama ke database
  const [result] = await db.execute(`
    INSERT INTO transaksi (nomor, tipe, gudang_id, tanggal, referensi, created_by)
    VALUES (?, ?, ?, ?, ?, ?)
  `, [nomor, tipe, gudang_id, tanggal, referensi || null, req.session.user.id]);

  const transaksi_id = result.insertId;

  // Menyimpan detail produk ke database
  for (let i = 0; i < produk_id.length; i++) {
    // Validasi jika ada data yang kosong
    if (!produk_id[i] || !qty[i] || !harga[i]) {
      continue; // Lewati jika data tidak lengkap
    }

    // Parsing qty dan harga ke tipe data yang sesuai
    const parsedQty = parseInt(qty[i], 10);
    const parsedHarga = parseFloat(harga[i]);

    // Skip jika data qty atau harga tidak valid
    if (isNaN(parsedQty) || isNaN(parsedHarga)) {
      continue; // Lewati data yang tidak valid
    }

    // Menyimpan detail transaksi ke database
    await db.execute(`
      INSERT INTO transaksi_detail (transaksi_id, produk_id, qty, harga)
      VALUES (?, ?, ?, ?)
    `, [transaksi_id, produk_id[i], parsedQty, parsedHarga]);
  }

  res.redirect('/transaksi');
});



// GET: Form edit transaksi
router.get('/transaksi/edit/:id', isAuthenticated, async (req, res) => {
  const transaksi_id = req.params.id;

  const [[transaksi]] = await db.execute('SELECT * FROM transaksi WHERE id = ?', [transaksi_id]);
  const [detail] = await db.execute('SELECT * FROM transaksi_detail WHERE transaksi_id = ?', [transaksi_id]);
  const [produk] = await db.execute('SELECT * FROM produk');
  const [gudang] = await db.execute('SELECT * FROM gudang');

  res.render('inventori/backend/editTransaksi', {
    title: 'Edit Transaksi',
    transaksi,
    detail,
    produk,
    gudang,
    user: req.session.user
  });
});

// POST: Update transaksi
router.post('/transaksi/edit/:id', isAuthenticated, async (req, res) => {
  const transaksi_id = req.params.id;
  const { nomor, tipe, gudang_id, tanggal, referensi, produk_id, qty, harga } = req.body;

  await db.execute(`
    UPDATE transaksi SET nomor = ?, tipe = ?, gudang_id = ?, tanggal = ?, referensi = ?
    WHERE id = ?
  `, [nomor, tipe, gudang_id, tanggal, referensi, transaksi_id]);

  await db.execute('DELETE FROM transaksi_detail WHERE transaksi_id = ?', [transaksi_id]);

  for (let i = 0; i < produk_id.length; i++) {
    await db.execute(`
      INSERT INTO transaksi_detail (transaksi_id, produk_id, qty, harga)
      VALUES (?, ?, ?, ?)
    `, [transaksi_id, produk_id[i], qty[i], harga[i]]);
  }

  res.redirect('/transaksi');
});

// GET: Hapus transaksi
router.get('/transaksi/delete/:id', isAuthenticated, async (req, res) => {
  const transaksi_id = req.params.id;

  await db.execute('DELETE FROM transaksi WHERE id = ?', [transaksi_id]);

  res.redirect('/transaksi');
});

// GET: Detail transaksi
router.get('/transaksi/:id', isAuthenticated, async (req, res) => {
  const transaksi_id = req.params.id;

  // Ambil data transaksi utama
  const [transaksi] = await db.execute(`
    SELECT t.*, g.nama_gudang
    FROM transaksi t
    JOIN gudang g ON t.gudang_id = g.id
    WHERE t.id = ?
  `, [transaksi_id]);

  if (!transaksi) {
    return res.status(404).send('Transaksi tidak ditemukan');
  }

  // Ambil detail transaksi dan pastikan harga dan total adalah angka
  const [transaksi_detail] = await db.execute(`
    SELECT td.qty, td.harga, (td.qty * td.harga) AS total, p.nama_produk
    FROM transaksi_detail td
    JOIN produk p ON td.produk_id = p.id
    WHERE td.transaksi_id = ?
  `, [transaksi_id]);

  // Pastikan detail.harga dan detail.total adalah angka
  transaksi_detail.forEach(detail => {
    detail.harga = parseFloat(detail.harga); // Konversi harga menjadi angka
    detail.total = parseFloat(detail.total); // Konversi total menjadi angka
  });

  // Kirim data transaksi dan detail transaksi ke tampilan
  res.render('inventori/table/transaksiDetail', {
    title: `Detail Transaksi - ${transaksi.nomor}`,
    transaksi: transaksi,
    transaksi_detail: transaksi_detail,
    user: req.session.user
  });
});




router.get('/laporan', isAuthenticated, async (req, res) => {
  const { start_date, end_date, gudang_id, tipe } = req.query;

  const filter = [];
  const values = [];

  if (start_date && end_date) {
    filter.push('t.tanggal BETWEEN ? AND ?');
    values.push(start_date, end_date);
  }

  if (gudang_id) {
    filter.push('t.gudang_id = ?');
    values.push(gudang_id);
  }

  if (tipe) {
    filter.push('t.tipe = ?');
    values.push(tipe);
  }

  const where = filter.length ? 'WHERE ' + filter.join(' AND ') : '';

  const [laporan] = await db.execute(`
  SELECT t.id, t.nomor, t.tanggal, t.tipe, t.referensi, g.nama_gudang, p.nama_produk, d.qty, d.harga, u.name AS nama_user
  FROM transaksi t
  JOIN gudang g ON t.gudang_id = g.id
  JOIN transaksi_detail d ON t.id = d.transaksi_id
  JOIN produk p ON d.produk_id = p.id
  LEFT JOIN users u ON t.created_by = u.id
  ${where}
  ORDER BY t.tanggal DESC
`, values);


  const [gudangs] = await db.execute('SELECT * FROM gudang');

  res.render('inventori/table/laporan', {
    title: "Laporan",
    user: req.session.user,
    laporan,
    gudangs,
    start_date,
    end_date,
    gudang_id,
    tipe
  });
});

// Rute untuk menampilkan faktur (invoice)
router.get('/transaksi/:id/invoice', isAuthenticated, async (req, res) => {
  const transaksi_id = req.params.id;

  try {
    // Ambil data transaksi utama
    const [transaksi] = await db.execute(`
      SELECT t.*, g.nama_gudang
      FROM transaksi t
      JOIN gudang g ON t.gudang_id = g.id
      WHERE t.id = ?
    `, [transaksi_id]);

    // Cek apakah transaksi ditemukan
    if (!transaksi || !transaksi.nomor) {
      return res.status(404).send('Transaksi tidak ditemukan atau nomor transaksi tidak tersedia');
    }

    // Ambil detail transaksi
    const [transaksi_detail] = await db.execute(`
      SELECT td.qty, td.harga, (td.qty * td.harga) AS total, p.nama_produk
      FROM transaksi_detail td
      JOIN produk p ON td.produk_id = p.id
      WHERE td.transaksi_id = ?
    `, [transaksi_id]);

    // Pastikan harga dan total adalah angka
    transaksi_detail.forEach(detail => {
      detail.harga = parseFloat(detail.harga); // Konversi harga menjadi angka
      detail.total = parseFloat(detail.total); // Konversi total menjadi angka
    });

    // Kirim data transaksi dan detail transaksi ke tampilan faktur
    res.render('inventori/table/invoice', {
      title: `Faktur - ${transaksi.nomor}`,
      transaksi: transaksi,
      transaksi_detail: transaksi_detail,
      user: req.session.user
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Terjadi kesalahan saat mengambil data transaksi');
  }
});



router.get("/kas-bank", isAuthenticated, (req, res) => {
  res.render("kas-bank", { title: "kas-bank", user: req.session.user });
});

module.exports = router;
