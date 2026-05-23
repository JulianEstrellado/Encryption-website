const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');

const app = express();
const upload = multer({ dest: 'temp/' });
const uploadDir = path.join(__dirname, 'uploads');
const tempDir = path.join(__dirname, 'temp');
const metadataFile = path.join(__dirname, 'metadata.json');

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    secret: 'replace-with-a-strong-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 2 * 60 * 60 * 1000 }
  })
);
app.use(express.static(path.join(__dirname, 'public')));

async function ensureStorage() {
  await fs.mkdir(uploadDir, { recursive: true });
  await fs.mkdir(tempDir, { recursive: true });
  try {
    await fs.access(metadataFile);
  } catch {
    await fs.writeFile(metadataFile, JSON.stringify({ users: [], files: [] }, null, 2));
  }
}

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 150000, 32, 'sha512');
}

async function readMetadata() {
  const raw = await fs.readFile(metadataFile, 'utf8');
  return JSON.parse(raw);
}

async function writeMetadata(data) {
  await fs.writeFile(metadataFile, JSON.stringify(data, null, 2));
}

function requireAuth(req, res, next) {
  if (req.session.username) {
    return next();
  }
  res.redirect('/login');
}

function isAuthorized(file, username) {
  return file.owner === username || (file.allowedUsers || []).includes(username);
}

app.get('/', (req, res) => {
  if (req.session.username) {
    return res.redirect('/upload');
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/register', (req, res) => {
  if (req.session.username) {
    return res.redirect('/upload');
  }
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!username || username.length < 3 || password.length < 8) {
    return res.status(400).send('Username must be at least 3 characters and password at least 8 characters.');
  }

  const metadata = await readMetadata();
  if (metadata.users.some((user) => user.username === username)) {
    return res.status(400).send('Username is already taken.');
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  metadata.users.push({ username, passwordHash, createdAt: new Date().toISOString() });
  await writeMetadata(metadata);

  req.session.username = username;
  res.redirect('/upload');
});

app.get('/login', (req, res) => {
  if (req.session.username) {
    return res.redirect('/upload');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  const metadata = await readMetadata();
  const user = metadata.users.find((entry) => entry.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).send('Invalid username or password.');
  }

  req.session.username = user.username;
  res.redirect('/upload');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/upload', requireAuth, async (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Security Share - Dashboard</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif;
            background: #f8f9fb;
            color: #111;
            margin: 0;
            min-height: 100vh;
          }

          .page {
            max-width: 1200px;
            margin: 0 auto;
            padding: 32px;
          }

          .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 24px;
            margin-bottom: 34px;
          }

          .brand {
            display: flex;
            align-items: center;
            gap: 14px;
          }

          .logo {
            font-size: 1.25rem;
            font-weight: 700;
            letter-spacing: -0.04em;
          }

          .topbar .button-link {
            border: 1px solid #111;
            background: white;
            color: #111;
            padding: 12px 22px;
            border-radius: 999px;
            text-decoration: none;
            font-weight: 600;
          }

          .topbar .button-link:hover {
            background: #f0f0f0;
          }

          .user-welcome {
            color: #444;
            font-size: 0.98rem;
          }

          .hero-header {
            margin-bottom: 32px;
          }

          .hero-header h1 {
            font-size: 2.8rem;
            margin-bottom: 10px;
            font-weight: 800;
          }

          .hero-header p {
            color: #555;
            font-size: 1rem;
            line-height: 1.6;
            max-width: 620px;
          }

          .main-grid {
            display: grid;
            grid-template-columns: 1.65fr 1fr;
            gap: 24px;
          }

          .upload-panel,
          .status-card,
          .info-card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 12px 34px rgba(15, 23, 42, 0.08);
            padding: 28px;
          }

          .upload-panel {
            display: flex;
            flex-direction: column;
            gap: 24px;
          }

          .upload-panel h2,
          .status-card h2,
          .info-card h2 {
            margin: 0 0 12px;
            font-size: 1.4rem;
          }

          .upload-panel p.description {
            margin: 0;
            color: #52575f;
            line-height: 1.7;
          }

          .drop-area {
            border: 2px dashed #d6d8dd;
            border-radius: 18px;
            min-height: 220px;
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center;
            padding: 28px;
            cursor: pointer;
            transition: border-color 0.2s, background 0.2s;
            background: #fbfcfd;
          }

          .drop-area.dragover {
            border-color: #111;
            background: #f5f6f8;
          }

          .drop-area p {
            margin: 0;
            color: #555;
            font-size: 1rem;
            line-height: 1.7;
          }

          .select-button {
            background: #111;
            color: white;
            border: none;
            padding: 10px 18px;
            border-radius: 999px;
            font-weight: 700;
            cursor: pointer;
            margin-top: 12px;
          }

          .select-button:hover {
            background: #333;
          }

          .field-group {
            display: grid;
            gap: 16px;
          }

          label {
            display: flex;
            flex-direction: column;
            font-weight: 600;
            color: #222;
            gap: 10px;
            font-size: 0.95rem;
          }

          input[type='password'],
          input[type='text'] {
            border: 1px solid #d6d8dd;
            border-radius: 14px;
            padding: 14px 16px;
            font-size: 1rem;
            background: #fff;
          }

          input[type='password']:focus,
          input[type='text']:focus {
            outline: none;
            border-color: #111;
          }

          .upload-actions {
            display: flex;
            justify-content: flex-start;
          }

          button.submit-button {
            background: #111;
            color: white;
            border: none;
            padding: 14px 26px;
            border-radius: 14px;
            font-size: 1rem;
            font-weight: 700;
            cursor: pointer;
          }

          button.submit-button:hover {
            background: #333;
          }

          .section-item {
            display: flex;
            flex-direction: column;
            gap: 8px;
            margin-bottom: 18px;
          }

          .section-item strong {
            font-size: 1rem;
            color: #111;
          }

          .section-item span {
            color: #57585f;
            font-size: 0.96rem;
          }

          @media (max-width: 980px) {
            .main-grid {
              grid-template-columns: 1fr;
            }
          }

          @media (max-width: 620px) {
            .page {
              padding: 20px;
            }

            .topbar {
              flex-direction: column;
              align-items: flex-start;
            }

            .hero-header h1 {
              font-size: 2.2rem;
            }
          }
        </style>
      </head>
      <body>
        <div class="page">
          <div class="topbar">
            <div class="brand">
              <div class="logo">Security Share</div>
            </div>
            <a class="button-link" href="/my-files">My Files</a>
            <div class="user-welcome">Welcome, <strong>${req.session.username}</strong></div>
          </div>

          <div class="hero-header">
            <h1>Upload and Encrypt Files</h1>
            <p>Securely share files using AES-256 Encryption</p>
          </div>

          <div class="main-grid">
            <section class="upload-panel">
              <div>
                <h2>Main File Upload</h2>
                <p class="description">Drag and drop a file below, or select one to upload. Enter a password and choose any users you want to grant access.</p>
              </div>

              <form method="POST" action="/upload" enctype="multipart/form-data">
                <div class="drop-area" id="dropzone">
                  <div>
                    <p>Drag & drop your file here</p>
                    <button type="button" class="select-button" id="selectFileBtn">Select files</button>
                    <p id="fileName" style="margin-top: 18px; color: #777;">No file selected</p>
                  </div>
                </div>

                <input type="file" id="fileInput" name="file" required hidden />

                <div class="field-group">
                  <label for="password">
                    Password
                    <input type="password" id="password" name="password" minlength="8" required placeholder="Enter encryption password" />
                  </label>

                  <label for="shareWith">
                    Share with users
                    <input type="text" id="shareWith" name="shareWith" placeholder="alice, bob" />
                  </label>
                </div>

                <div class="upload-actions">
                  <button type="submit" class="submit-button">Encrypt and upload</button>
                </div>
              </form>
            </section>

            <div style="display:flex; flex-direction:column; gap:24px;">
              <section class="status-card">
                <h2>Security Status</h2>
                <div class="section-item">
                  <strong>AES-256 Encryption</strong>
                  <span>Military-grade Encryption</span>
                </div>
                <div class="section-item">
                  <strong>Password Protected</strong>
                  <span>Custom Encryption Keys</span>
                </div>
                <div class="section-item">
                  <strong>Authorized Access</strong>
                  <span>User-based Permissions</span>
                </div>
              </section>

              <section class="info-card">
                <h2>Encryption info</h2>
                <div class="section-item">
                  <strong>AES-256-CBC</strong>
                  <span>Industry-standard encryption algorithm</span>
                </div>
                <div class="section-item">
                  <strong>PBKDF2</strong>
                  <span>Key derivation function for password security.</span>
                </div>
              </section>
            </div>
          </div>
        </div>

        <script>
          const dropzone = document.getElementById('dropzone');
          const fileInput = document.getElementById('fileInput');
          const fileName = document.getElementById('fileName');
          const selectFileBtn = document.getElementById('selectFileBtn');

          const updateFileName = () => {
            if (fileInput.files.length > 0) {
              fileName.textContent = fileInput.files[0].name;
            } else {
              fileName.textContent = 'No file selected';
            }
          };

          const openFileDialog = () => fileInput.click();

          dropzone.addEventListener('click', openFileDialog);
          selectFileBtn.addEventListener('click', openFileDialog);

          dropzone.addEventListener('dragover', (event) => {
            event.preventDefault();
            dropzone.classList.add('dragover');
          });

          dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('dragover');
          });

          dropzone.addEventListener('drop', (event) => {
            event.preventDefault();
            dropzone.classList.remove('dragover');
            if (event.dataTransfer.files.length > 0) {
              fileInput.files = event.dataTransfer.files;
              updateFileName();
            }
          });

          fileInput.addEventListener('change', updateFileName);
        </script>
      </body>
    </html>
  `);
});

app.get('/my-files', requireAuth, async (req, res) => {
  const metadata = await readMetadata();
  const owned = metadata.files.filter((file) => file.owner === req.session.username);
  const shared = metadata.files.filter((file) => file.allowedUsers?.includes(req.session.username));

  function renderList(files) {
    if (!files.length) {
      return '<p class="empty-state">No files found.</p>';
    }

    return `<div class="file-list">${files
      .map(
        (file) => `
          <div class="file-card">
            <div class="file-name">${file.originalName}</div>
            <div class="file-meta">
              <span><strong>Owner:</strong> ${file.owner}</span>
              <span><strong>Shared with:</strong> ${file.allowedUsers?.join(', ') || 'none'}</span>
              <span><strong>Expires:</strong> ${file.expiresAt}</span>
            </div>
            <a class="download-link" href="/download/${file.id}">Download</a>
          </div>`
      )
      .join('')}</div>`;
  }

  res.send(`
    <html>
      <head>
        <title>Security Share - My Files</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif;
            background: #f8f9fb;
            color: #111;
            margin: 0;
            min-height: 100vh;
          }

          .page {
            max-width: 1180px;
            margin: 0 auto;
            padding: 32px;
          }

          .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 32px;
          }

          .brand {
            display: flex;
            align-items: center;
          }

          .logo {
            font-size: 1.25rem;
            font-weight: 700;
            letter-spacing: -0.04em;
          }

          .nav-links {
            display: flex;
            gap: 14px;
            align-items: center;
            flex-wrap: wrap;
          }

          .nav-links a {
            text-decoration: none;
            color: #111;
            border: 1px solid #111;
            padding: 10px 18px;
            border-radius: 999px;
            font-weight: 600;
            background: white;
          }

          .nav-links a:hover {
            background: #f0f0f0;
          }

          .welcome-text {
            color: #555;
            font-size: 0.98rem;
          }

          .content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
          }

          .panel {
            background: white;
            border-radius: 20px;
            box-shadow: 0 12px 34px rgba(15, 23, 42, 0.08);
            padding: 28px;
          }

          .panel h2 {
            margin-top: 0;
            margin-bottom: 18px;
            font-size: 1.5rem;
          }

          .panel p.description {
            color: #555;
            line-height: 1.7;
            margin-bottom: 24px;
          }

          .file-card {
            border: 1px solid #ececec;
            border-radius: 16px;
            padding: 18px 20px;
            margin-bottom: 18px;
            background: #fafbfc;
          }

          .file-name {
            font-weight: 700;
            margin-bottom: 10px;
            color: #111;
          }

          .file-meta {
            display: grid;
            gap: 8px;
            margin-bottom: 14px;
            color: #555;
            font-size: 0.94rem;
          }

          .download-link {
            display: inline-block;
            color: #111;
            font-weight: 700;
            text-decoration: none;
            padding: 10px 16px;
            border-radius: 12px;
            border: 1px solid #111;
            background: white;
          }

          .download-link:hover {
            background: #f5f5f5;
          }

          .empty-state {
            color: #777;
            padding: 18px;
            border: 1px dashed #d6d8dd;
            border-radius: 16px;
            background: #fbfcfd;
          }

          @media (max-width: 940px) {
            .content {
              grid-template-columns: 1fr;
            }
          }

          @media (max-width: 620px) {
            .page {
              padding: 20px;
            }

            .topbar {
              flex-direction: column;
              align-items: flex-start;
            }
          }
        </style>
      </head>
      <body>
        <div class="page">
          <div class="topbar">
            <div class="brand">
              <div class="logo">Security Share</div>
            </div>
            <div class="nav-links">
              <a href="/upload">Upload</a>
              <a href="/logout">Logout</a>
            </div>
            <div class="welcome-text">Signed in as <strong>${req.session.username}</strong></div>
          </div>

          <div class="content">
            <section class="panel">
              <h2>Owned files</h2>
              ${renderList(owned)}
            </section>

            <section class="panel">
              <h2>Shared with me</h2>
              ${renderList(shared)}
            </section>
          </div>
        </div>
      </body>
    </html>
  `);
});

app.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    const { password, shareWith = '' } = req.body;
    if (!req.file || !password || password.length < 8) {
      await fs.unlink(req.file?.path).catch(() => undefined);
      return res.status(400).send('File and password are required. Password must be at least 8 characters.');
    }

    const metadata = await readMetadata();
    const usernames = shareWith
      .split(',')
      .map((name) => name.trim().toLowerCase())
      .filter((name) => name && name !== req.session.username);

    const invalidUser = usernames.find((name) => !metadata.users.some((user) => user.username === name));
    if (invalidUser) {
      await fs.unlink(req.file.path).catch(() => undefined);
      return res.status(400).send(`User '${invalidUser}' does not exist.`);
    }

    const fileId = uuidv4();
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const key = deriveKey(password, salt);

    const fileBuffer = await fs.readFile(req.file.path);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const outputPath = path.join(uploadDir, `${fileId}.enc`);

    await fs.writeFile(outputPath, Buffer.concat([salt, iv, authTag, encrypted]));
    await fs.unlink(req.file.path).catch(() => undefined);

    metadata.files.push({
      id: fileId,
      originalName: req.file.originalname,
      owner: req.session.username,
      allowedUsers: usernames,
      size: req.file.size,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
    });
    await writeMetadata(metadata);

    const downloadUrl = `${req.protocol}://${req.get('host')}/download/${fileId}`;
    res.send(`Upload complete. Share this link with authorized users:<br><a href="${downloadUrl}">${downloadUrl}</a><br><p><a href="/upload">Upload another file</a> | <a href="/my-files">My files</a></p>`);
  } catch (error) {
    console.error(error);
    res.status(500).send('Encryption failed.');
  }
});

app.get('/download/:id', requireAuth, async (req, res) => {
  const fileId = req.params.id;
  const metadata = await readMetadata();
  const file = metadata.files.find((entry) => entry.id === fileId);
  if (!file) {
    return res.status(404).send('File not found.');
  }

  if (!isAuthorized(file, req.session.username)) {
    return res.status(403).send('You do not have permission to download this file.');
  }

  res.send(`
    <html>
      <head><title>Download file</title></head>
      <body style="font-family: Arial, sans-serif; padding: 40px; background: #f4f6fb; color: #222;">
        <div style="max-width: 520px; margin:0 auto; background:#fff; padding:28px; border-radius:12px; box-shadow:0 18px 40px rgba(0,0,0,0.08);">
          <h1>Download "${file.originalName}"</h1>
          <p>Signed in as <strong>${req.session.username}</strong>. <a href="/my-files">My files</a> | <a href="/logout">Logout</a></p>
          <form method="POST" action="/download/${fileId}">
            <label>Password:<br><input type="password" name="password" required style="width:100%; padding:10px; margin-top:8px; border:1px solid #dde3f0; border-radius:8px;" /></label>
            <button type="submit" style="margin-top:18px; padding:12px 18px; background:#3239ff; color:#fff; border:none; border-radius:10px; cursor:pointer;">Download securely</button>
          </form>
        </div>
      </body>
    </html>
  `);
});

app.post('/download/:id', requireAuth, async (req, res) => {
  try {
    const fileId = req.params.id;
    const password = String(req.body.password || '');
    if (!password) return res.status(400).send('Password required.');

    const metadata = await readMetadata();
    const file = metadata.files.find((entry) => entry.id === fileId);
    if (!file) return res.status(404).send('File not found.');
    if (!isAuthorized(file, req.session.username)) {
      return res.status(403).send('You do not have permission to download this file.');
    }

    const encryptedPath = path.join(uploadDir, `${fileId}.enc`);
    const payload = await fs.readFile(encryptedPath);

    const salt = payload.slice(0, 16);
    const iv = payload.slice(16, 28);
    const authTag = payload.slice(28, 44);
    const ciphertext = payload.slice(44);
    const key = deriveKey(password, salt);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.originalName)}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(decrypted);
  } catch (error) {
    console.error(error);
    res.status(400).send('Unable to decrypt file. Verify the password and try again.');
  }
});

app.listen(3000, async () => {
  await ensureStorage();
  console.log('Secure file sharing app running on http://localhost:3000');
});
