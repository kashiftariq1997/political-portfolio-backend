import express from "express";
import mongoose from "mongoose";
import multer from "multer";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cors from "cors";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

dotenv.config();
// Determine __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use("/temp", express.static(path.join(__dirname, "temp")));

// Create the temp directory if it doesn't exist
const tempDir = path.join(__dirname, "temp");
if (!fs.existsSync(tempDir)) {
  fs.mkdirSync(tempDir, { recursive: true });
}

// Database Connection
mongoose
  .connect(process.env.DATABASE_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error(err));

// Mongoose Schemas and Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

// Seeder to create an admin user
async function seedAdminUser() {
  const adminExists = await User.findOne({ username: "admin" });
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash("admin123", 10);
    const admin = new User({
      username: "admin",
      password: hashedPassword,
    });
    await admin.save();
    console.log("Admin user created");
  }
}
seedAdminUser();

// Login API
app.post("/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    res.json({ token });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Middleware for Admin Authentication
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Access denied" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
}

const titleSchema = new mongoose.Schema({
  text: { type: String, required: true },
  image: { type: String, required: true },
  active: { type: Boolean, default: true },
});

const contentSchema = new mongoose.Schema({
  text: { type: String, required: true },
  image: { type: String },
  order: { type: Number, required: true },
  published: { type: Boolean, default: false },
});

const voteSchema = new mongoose.Schema({
  ip: { type: String },
  partyName: { type: String },
});

const VolunteerSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: true,
      trim: true,
    },
    lastName: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    phone: {
      type: String,
      required: true,
      trim: true,
    },
    date: {
      type: Date,
      required: true,
    },
    gender: {
      type: String,
      required: true,
      enum: ["male", "female"],
    },
    address: {
      type: String,
      required: true,
      trim: true,
    },
    ip: { type: String },
  },
  { timestamps: true }
);

// Create the model
const Volunteer = mongoose.model("Volunteer", VolunteerSchema);

const Title = mongoose.model("Title", titleSchema);
const Content = mongoose.model("Content", contentSchema);
const Vote = mongoose.model("Vote", voteSchema);

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
    const allowedMimeTypes = ["image/jpeg", "image/png", "image/gif"];
    if (!allowedMimeTypes.includes(file.mimetype)) {
      return cb(
        new Error("Invalid file type. Only JPEG, PNG, and GIF are allowed.")
      );
    }
    cb(null, true);
  },
});

// Admin APIs
// Create Title
app.post("/admin/titles", upload.single("image"), async (req, res) => {
  try {
    const { text, active } = req.body;
    const image = `/temp/${req.file.filename}`;

    // Deactivate other titles if this one is active
    if (active === "true") {
      await Title.updateMany({}, { $set: { active: false } });
    }

    const title = new Title({ text, image, active: active === "true" });
    await title.save();

    res.status(201).send(title);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Update Title
app.put("/admin/titles/:id", upload.single("image"), async (req, res) => {
  try {
    const { text, active } = req.body;
    const title = await Title.findById(req.params.id);

    if (!title) {
      return res.status(404).send({ message: "Title not found" });
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

    // Deactivate other titles if this one is active
    if (active === "true") {
      await Title.updateMany({}, { $set: { active: false } });
      updateData.active = true;
    } else {
      updateData.active = false;
    }

    const updatedTitle = await Title.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    );
    res.send(updatedTitle);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Create Content
app.post("/admin/contents", upload.single("image"), async (req, res) => {
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
app.put("/admin/contents/:id", upload.single("image"), async (req, res) => {
  try {
    const { text, order, published } = req.body;
    const contentToUpdate = await Content.findById(req.params.id);

    if (!contentToUpdate) {
      return res.status(404).send({ message: "Content not found" });
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

    const updatedContent = await Content.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    );
    res.send(updatedContent);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.get("/admin/contents", async (req, res) => {
  try {
    const contents = await Content.find().sort({ order: 1 });
    res.send(contents);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.get("/admin/titles", async (req, res) => {
  try {
    const titles = await Title.find();
    res.send(titles);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.delete("/admin/contents/:id", async (req, res) => {
  try {
    const content = await Content.findByIdAndDelete(req.params.id);
    if (!content) {
      return res.status(404).send("Content not found");
    }
    res.status(200).send({ message: "Content deleted successfully", content });
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.delete("/admin/titles/:id", async (req, res) => {
  try {
    const title = await Title.findByIdAndDelete(req.params.id);
    if (!title) {
      return res.status(404).send("Title not found");
    }
    res.status(200).send({ message: "Title deleted successfully", title });
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Public APIs
// Get Titles
app.get("/public/titles", async (req, res) => {
  try {
    const titles = await Title.find({ active: true });

    if (titles.length) {
      res.send(titles);
    } else {
      const inactive = await Title.find();
      res.send(inactive);
    }
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.get("/public/titles/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const title = await Title.findById(id);

    if (!title) {
      return res.status(404).send("Title not found");
    }

    res.send(title);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Get Published Contents
app.get("/public/contents", async (req, res) => {
  try {
    const contents = await Content.find({ published: true }).sort({ order: 1 });
    res.send(contents);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.get("/public/contents/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const content = await Content.findById(id);

    if (!content) {
      return res.status(404).send("Content not found");
    }

    res.send(content);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.post("/vote", async (req, res) => {
  const { partyName } = req.body;

  const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  console.log("Client IP Address:", clientIp);

  try {
    const existingVote = await Vote.findOne({ ip: clientIp });
    if (existingVote) {
      return res.status(400).json({
        message: "You already voted",
      });
    }
    const newVote = await Vote.create({
      ip: clientIp,
      partyName,
    });

    res.status(201).json({
      message: `Your vote for ${partyName} successfully submitted`,
      vote: newVote,
    });
  } catch (error) {
    res.status(500).json({
      message: "Error recording vote",
      error: error.message,
    });
  }
});

app.post("/volunteer", async (req, res) => {
  console.log(">>>>>>>>>>>>>>>>>>>:::::::::::::::::;", req.body);
  try {
    const { firstName, lastName, email, phone, date, gender, address } =
      req.body;
    const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

    const existingVolunteer = await Volunteer.findOne({ email });
    if (existingVolunteer) {
      return res.status(400).json({
        message: "Email already exists",
      });
    }

    const volunteer = new Volunteer({
      firstName,
      lastName,
      email,
      phone,
      date,
      gender,
      address,
      ip: clientIp,
    });

    // Save to the database
    await volunteer.save();

    res.status(201).json({
      message: "You are successfully become a Volunteer",
      data: volunteer,
    });
  } catch (error) {
    console.error("Error creating volunteer:", error);
    res.status(500).json({
      message: "An error occurred while creating the volunteer",
      error: error.message,
    });
  }
});

app.get("/get-IP/:tableName", async (req, res) => {
  const { tableName } = req.params;
  console.log(">>>>>>.", tableName);
  try {
    const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    console.log("Client IP Address:", clientIp);

    let existingIp;

    if (tableName == "Vote") {
      existingIp = await Vote.findOne({ ip: clientIp });
    } else {
      existingIp = await Volunteer.findOne({ ip: clientIp });
    }
    if (existingIp) {
      res.status(200).json({ message: "IP exists", ip: clientIp });
    } else {
      res
        .status(200)
        .json({ message: "IP not found", ip: clientIp });
    }
  } catch (error) {
    console.error(
      "Error while fetching client IP or querying database:",
      error.message
    );
    res.status(500).json({ error: "An internal server error occurred." });
  }
});

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
