import express from 'express';
import mongoose from 'mongoose';
import multer from 'multer';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();
// Determine __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use('/temp', express.static(path.join(__dirname, 'temp')));

// Create the temp directory if it doesn't exist
const tempDir = path.join(__dirname, 'temp');
if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
}

// Database Connection
mongoose.connect('mongodb://localhost:27017/node_mongo_app', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB')).catch(err => console.error(err));


// Mongoose Schemas and Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Seeder to create an admin user
async function seedAdminUser() {
  const adminExists = await User.findOne({ username: 'admin' });
  if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      const admin = new User({
          username: 'admin',
          password: hashedPassword,
      });
      await admin.save();
      console.log('Admin user created');
  }
}
seedAdminUser();

// Login API
app.post('/admin/login', async (req, res) => {
  try {
      const { username, password } = req.body;
      const user = await User.findOne({ username });
      if (!user) {
          return res.status(401).json({ message: 'Invalid credentials' });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
          return res.status(401).json({ message: 'Invalid credentials' });
      }

      const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, {
          expiresIn: '1h',
      });

      res.json({ token });
  } catch (error) {
      res.status(500).send(error.message);
  }
});

// Middleware for Admin Authentication
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
      return res.status(401).json({ message: 'Access denied' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
          return res.status(403).json({ message: 'Invalid token' });
      }
      req.user = user;
      next();
  });
}

const titleSchema = new mongoose.Schema({
    text: { type: String, required: true },
    image: { type: String, required: true },
});

const contentSchema = new mongoose.Schema({
    text: { type: String, required: true },
    image: { type: String, required: true },
    order: { type: Number, required: true },
    published: { type: Boolean, default: false },
});

const Title = mongoose.model('Title', titleSchema);
const Content = mongoose.model('Content', contentSchema);

// Multer Setup for File Uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, tempDir);
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    },
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB file size limit
    fileFilter: (req, file, cb) => {
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];
        if (!allowedMimeTypes.includes(file.mimetype)) {
            return cb(new Error('Invalid file type. Only JPEG, PNG, and GIF are allowed.'));
        }
        cb(null, true);
    },
});

// Admin APIs
// Create Title
app.post('/admin/title', upload.single('image'), async (req, res) => {
    try {
        const { text } = req.body;
        const image = `/temp/${req.file.filename}`;
        const title = new Title({ text, image });
        await title.save();
        res.status(201).send(title);
    } catch (err) {
        res.status(400).send(err.message);
    }
});

// Update Title
app.put('/admin/title/:id', upload.single('image'), async (req, res) => {
    try {
        const { text } = req.body;
        const title = await Title.findById(req.params.id);

        if (!title) {
            return res.status(404).send({ message: 'Title not found' });
        }

        const updateData = { text };
        if (req.file) {
            // Delete the old image
            const oldImagePath = path.join(__dirname, title.image);
            if (fs.existsSync(oldImagePath)) {
                fs.unlinkSync(oldImagePath);
            }

            updateData.image = `/temp/${req.file.filename}`;
        }

        const updatedTitle = await Title.findByIdAndUpdate(req.params.id, updateData, { new: true });
        res.send(updatedTitle);
    } catch (err) {
        res.status(400).send(err.message);
    }
});

// Create Content
app.post('/admin/content', upload.single('image'), async (req, res) => {
    try {
        const { text, published } = req.body;
        const image = `/temp/${req.file.filename}`;

        // Calculate default order
        const count = await Content.countDocuments();
        const order = count + 1;

        const content = new Content({ text, image, order, published });
        await content.save();
        res.status(201).send(content);
    } catch (err) {
        res.status(400).send(err.message);
    }
});

// Update Content
app.put('/admin/content/:id', upload.single('image'), async (req, res) => {
    try {
        const { text, order, published } = req.body;
        const contentToUpdate = await Content.findById(req.params.id);

        if (!contentToUpdate) {
            return res.status(404).send({ message: 'Content not found' });
        }

        const updateData = { text, published };
        if (req.file) {
            // Delete the old image
            const oldImagePath = path.join(__dirname, contentToUpdate.image);
            if (fs.existsSync(oldImagePath)) {
                fs.unlinkSync(oldImagePath);
            }

            updateData.image = `/temp/${req.file.filename}`;
        }

        // If order is being changed, adjust other contents' order
        if (order && order !== contentToUpdate.order) {
            const existingOrder = contentToUpdate.order;
            updateData.order = order;

            if (order > existingOrder) {
                await Content.updateMany(
                    { order: { $gt: existingOrder, $lte: order } },
                    { $inc: { order: -1 } }
                );
            } else {
                await Content.updateMany(
                    { order: { $lt: existingOrder, $gte: order } },
                    { $inc: { order: 1 } }
                );
            }
        }

        const updatedContent = await Content.findByIdAndUpdate(req.params.id, updateData, { new: true });
        res.send(updatedContent);
    } catch (err) {
        res.status(400).send(err.message);
    }
});

// Public APIs
// Get Titles
app.get('/public/titles', async (req, res) => {
    try {
        const titles = await Title.find();
        res.send(titles);
    } catch (err) {
        res.status(400).send(err.message);
    }
});

// Get Published Contents
app.get('/public/contents', async (req, res) => {
    try {
        const contents = await Content.find({ published: true }).sort({ order: 1 });
        res.send(contents);
    } catch (err) {
        res.status(400).send(err.message);
    }
});

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
