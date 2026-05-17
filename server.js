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
        <title>Upload - Secure Sharing</title>
        <style>body { font-family: Arial, sans-serif; background: #f4f6fb; color: #222; padding: 40px; } .card { max-width: 520px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 18px 40px rgba(0,0,0,0.08); padding: 32px; } label { display:block; margin-bottom:18px; } input, button { width:100%; padding:12px 14px; border-radius:8px; border:1px solid #dde3f0; } button { background:#3239ff; color:#fff; border:none; cursor:pointer; margin-top:12px; } a { color:#3239ff; }</style>
      </head>
      <body>
        <div class="card">
          <h1>Secure Upload</h1>
          <p>Signed in as <strong>${req.session.username}</strong>. <a href="/my-files">My files</a> | <a href="/logout">Logout</a></p>
          <form method="POST" action="/upload" enctype="multipart/form-data">
            <label>Choose file<input type="file" name="file" required></label>
            <label>Password (min 8 chars)<input type="password" name="password" minlength="8" required></label>
            <label>Share with users (comma separated usernames)<input type="text" name="shareWith" placeholder="alice, bob"></label>
            <button type="submit">Encrypt and upload</button>
          </form>
          <p style="margin-top:16px; font-size:14px; color:#555;">Files are encrypted with a password and only accessible to the owner or listed users.</p>
        </div>
      </body>
    </html>
  `);
});

app.get('/my-files', requireAuth, async (req, res) => {
  const metadata = await readMetadata();
  const owned = metadata.files.filter((file) => file.owner === req.session.username);
  const shared = metadata.files.filter((file) => file.allowedUsers?.includes(req.session.username));

  function renderList(files) {
    if (!files.length) return '<p>No files found.</p>';
    return `<ul>${files
      .map(
        (file) => `<li><strong>${file.originalName}</strong> - <a href="/download/${file.id}">Download</a><br>Owner: ${file.owner}<br>Shared with: ${file.allowedUsers?.join(', ') || 'none'}<br>Expires: ${file.expiresAt}</li>`
      )
      .join('')}</ul>`;
  }

  res.send(`
    <html>
      <head>
        <title>My Files - Secure Sharing</title>
        <style>body { font-family: Arial, sans-serif; background: #f4f6fb; color: #222; padding: 40px; } .card { max-width: 720px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 18px 40px rgba(0,0,0,0.08); padding: 32px; } a { color: #3239ff; }</style>
      </head>
      <body>
        <div class="card">
          <h1>My Files</h1>
          <p>Signed in as <strong>${req.session.username}</strong>. <a href="/upload">Upload</a> | <a href="/logout">Logout</a></p>
          <h2>Owned files</h2>
          ${renderList(owned)}
          <h2>Shared with me</h2>
          ${renderList(shared)}
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
