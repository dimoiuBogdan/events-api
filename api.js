import {
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import { rateLimit } from "express-rate-limit";
import jwt from "jsonwebtoken";
import multer from "multer";
import mysql from "mysql2";
import nodemailer from "nodemailer";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

const database = mysql
  .createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT || undefined,
    ssl: {
      rejectUnauthorized: false,
    },
  })
  .promise();

const postLimiter = rateLimit({
  windowMs: 5000, // 10 seconds
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: "Too many requests from this IP, please try again later.",
});

const secureLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: "Too many requests from this IP, please try again later.",
});

// --------------------------- S3 Images ---------------------------

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const S3 = new S3Client({
  region: "auto",
  endpoint: process.env.S3_ENDPOINT,
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
  },
});

const uploadFile = async (file, userId) => {
  const command = new PutObjectCommand({
    Body: file.buffer,
    Bucket: "events-images",
    Key: `${userId}.jpg`,
    ContentType: file.mimetype,
  });

  try {
    await S3.send(command);

    return true;
  } catch (err) {
    console.log(err);
  }

  return false;
};

const getFile = async (userId) => {
  const command = new GetObjectCommand({
    Bucket: "events-images",
    Key: `${userId}.jpg`,
  });

  try {
    const response = await S3.send(command);

    const body = response.Body;

    return body;
  } catch (err) {
    return;
  }
};

app.post(
  "/upload-profile-image/:userId",
  upload.single("imageFormData"),
  async (req, res) => {
    const userId = req.params.userId;
    const image = req.file;

    if (!image) {
      return res.status(400).json({ error: "No image provided" });
    }

    const uploaded = await uploadFile(image, userId);

    if (!uploaded) {
      return res.status(500).json({ error: "Failed to upload image" });
    }

    res.status(200).json({ message: "Image uploaded successfully" });
  }
);

app.get("/get-profile-image/:userId", async (req, res) => {
  const userId = req.params.userId;

  const file = await getFile(userId);

  if (!file) {
    return res.status(204).json({ error: "File not found" });
  }

  res.setHeader("Content-Type", "image/jpeg");

  file.pipe(res);

  res.status(200);
});

// --------------------------- USERS ---------------------------

const findUserBasedOnEmail = async (email, password) => {
  const query = `
      SELECT *
      FROM users
      WHERE email = ?`;

  const [rows] = await database.query(query, [email]);

  const user = rows[0];

  if (!user || user.email !== email) {
    return undefined;
  }

  return {
    id: user.id,
    email: user.email,
  };
};

const findUserBasedOnCredentials = async (email, password) => {
  const query = `
      SELECT *
      FROM users
      WHERE email = ?`;

  const [rows] = await database.query(query, [email]);

  const user = rows[0];

  if (!user || user.password !== password) {
    return undefined;
  }

  return {
    id: user.id,
    email: user.email,
  };
};

const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json("You are not authorized");
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json("Invalid token");
    }

    req.user = user;
    next();
  });
};

const generateAccessToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "24h" }
  );
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
    },
    process.env.REFRESH_TOKEN_SECRET
  );
};

const getUserById = async (userId) => {
  const query = `
      SELECT *
      FROM users
      WHERE id = ?`;

  const [rows] = await database.query(query, [userId]);

  return rows[0];
};

const updateUserData = async (userId, data, key) => {
  const query = `
      UPDATE users
      SET ${key} = ?
      WHERE id = ?`;

  await database.query(query, [data, userId]);

  return true;
};

app.post("/users/register", secureLimiter, async (req, res) => {
  const {
    email,
    password,
    first_name,
    last_name,
    phone_number,
    confirm_password,
  } = req.body;

  if (
    !email ||
    !password ||
    !first_name ||
    !last_name ||
    !phone_number ||
    !confirm_password
  )
    return res.status(400).json({
      message: "Missing required fields",
    });

  if (password !== confirm_password)
    return res.status(400).json({
      message: "Passwords do not match",
    });

  const user = await findUserBasedOnCredentials(email, password);

  if (user) {
    return res.status(409).json({
      message: "User already exists",
    });
  }

  const query = `
      INSERT INTO users (email, password, first_name, last_name, phone_number)
      VALUES (?, ?, ?, ?, ?)`;

  const [rows] = await database.query(query, [
    email,
    password,
    first_name,
    last_name,
    phone_number,
  ]);

  const user_id = rows.insertId;

  const accessToken = generateAccessToken({
    id: user_id,
    email,
  });

  const refreshToken = generateRefreshToken({
    id: user_id,
    email,
  });

  res.json({ id: user_id, email, accessToken, refreshToken });
});

app.post("/users/login", secureLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "Missing required fields",
    });
  }

  const user = await findUserBasedOnCredentials(email, password);

  if (!user) {
    return res.status(401).json({
      message: "Invalid credentials",
    });
  }

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  res.json({ id: user.id, email: user.email, accessToken, refreshToken });
});

app.post("/users/logout", async (req, res) => {
  res.status(200).json({ message: "Logged out successfully" });
});

app.post("/users/refresh", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({
      message: "You are not authenticated",
    });
  }

  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, user) => {
      if (err) {
        return res.status(403).json({
          message: "Invalid refresh token",
        });
      }

      const newAccessToken = generateAccessToken(user);
      const newRefreshToken = generateRefreshToken(user);

      res
        .status(200)
        .json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
    }
  );
});

app.get("/users/:id", verifyToken, async (req, res) => {
  const { id } = req.params;

  const user = await getUserById(id);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  res.json(user);
});

app.patch("/users/:id", [postLimiter, verifyToken], async (req, res) => {
  const { id } = req.params;

  const { key, value } = req.body;

  const updated = await updateUserData(id, value, key);

  if (!updated) {
    return res.status(404).json({ message: "User not found" });
  }

  res.sendStatus(204);
});

// --------------------------- FORGOT PASSWORD ---------------------------

const generateResetToken = (user) => {
  const payload = {
    id: user.id,
    email: user.email,
  };

  return jwt.sign(payload, process.env.RESET_TOKEN_SECRET, {
    expiresIn: "1h",
  });
};

const isValidResetToken = (token) => {
  try {
    jwt.verify(token, process.env.RESET_TOKEN_SECRET);
    return true;
  } catch (err) {
    return false;
  }
};

const getUserIdFromResetToken = (token) => {
  try {
    const { id } = jwt.verify(token, process.env.RESET_TOKEN_SECRET);
    return id;
  } catch (err) {
    return null;
  }
};

const setNewPassword = async (password, userId) => {
  const query = `
      UPDATE users
      SET password = ?
      WHERE id = ?`;

  const [rows] = await database.query(query, [password, userId]);

  return rows;
};

const sendResetPasswordEmail = async (user, resetToken) => {
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.net",
    service: "gmail",
    auth: {
      user: process.env.SMTP_FROM,
      pass: process.env.SMTP_PASS,
    },
  });

  const mailOptions = {
    from: `Bobivents ${process.env.SMTP_FROM}`,
    to: user.email,
    subject: "Reset Password",
    text: `Click here to reset your password: ${process.env.CLIENT_URL}/forgot-password/${resetToken}`,
  };

  return await transporter.sendMail(mailOptions);
};

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      message: "Missing required fields",
    });
  }

  const user = await findUserBasedOnEmail(email);

  if (!user) {
    return res.status(404).json({
      message: "User not found",
    });
  }

  const resetToken = generateResetToken(user);

  const sendEmail = await sendResetPasswordEmail(user, resetToken);

  if (!sendEmail) {
    return res.status(500).json({
      message: "Failed to send email",
    });
  }

  res.sendStatus(200);
});

app.post("/verify-reset-token", async (req, res) => {
  const { resetToken } = req.body;

  if (!resetToken) {
    return res.status(400).json({
      message: "Missing required fields",
    });
  }

  const validToken = isValidResetToken(resetToken);

  if (!validToken) {
    return res.status(403).json({
      message: "Invalid token",
    });
  }

  res.sendStatus(200);
});

app.post("/set-new-password", async (req, res) => {
  const { resetToken, password } = req.body;

  if (!resetToken || !password) {
    return res.status(400).json({
      message: "Missing required fields",
    });
  }

  const validToken = isValidResetToken(resetToken);

  const userId = getUserIdFromResetToken(resetToken);

  if (!validToken) {
    return res.status(403).json({
      message: "Invalid token",
    });
  }

  const newPasswordSet = setNewPassword(password, userId);

  if (!newPasswordSet) {
    return res.status(403).json({
      message: "Invalid token",
    });
  }

  res.sendStatus(200);
});

// --------------------------- EVENTS ---------------------------

const createEvent = async (event, user_id) => {
  const { name, description, location, from_date, to_date, contact } = event;

  const query = `
        INSERT INTO events (name, description, location, from_date, to_date, contact, user_id) 
        VALUES (?, ?, ?, ?, ?, ?, ${user_id})`;

  const [rows] = await database.query(query, [
    name,
    description,
    location,
    from_date,
    to_date,
    contact,
  ]);

  return rows.insertId;
};

const getEventForCertainDate = async (date, user_id) => {
  const query = `
        SELECT * 
        FROM events
        WHERE DATE(from_date) = ?
        AND user_id = ${user_id}`;

  const MILISECONDS_IN_AN_HOUR = 60 * 60 * 1000;

  const differenceBetweenZuluAndLocalTimezone =
    new Date(date).getTimezoneOffset() / 60;

  const parsedDate = new Date(
    new Date(date).getTime() -
      differenceBetweenZuluAndLocalTimezone * MILISECONDS_IN_AN_HOUR
  ).toISOString();

  const [rows] = await database.query(query, [parsedDate]);

  return rows;
};

const getEvents = async (user_id) => {
  const query = `
        SELECT * 
        FROM events
        WHERE user_id = ${user_id}`;

  const [rows] = await database.query(query);

  return rows;
};

const getEventById = async (id, user_id) => {
  const query = `
        SELECT * 
        FROM events
        WHERE id = ?
        AND user_id = ${user_id}`;

  const [rows] = await database.query(query, [id]);

  return rows[0];
};

const removeEvent = async (id, user_id) => {
  const query = `
        DELETE FROM events
        WHERE id = ?
        AND user_id = ${user_id}`;

  await database.query(query, [id]);

  return true;
};

const updateEvent = async (id, updatedEvent) => {
  const { name, description, location, from_date, to_date, contact } =
    updatedEvent;

  const query = `
        UPDATE events
        SET name = ?, description = ?, location = ?, from_date = ?, to_date = ?, contact = ?
        WHERE id = ?`;

  await database.query(query, [
    name,
    description,
    location,
    from_date,
    to_date,
    contact,
    id,
  ]);

  return true;
};

app.get("/events/date", [postLimiter, verifyToken], async (req, res) => {
  const { date } = req.query;
  const userId = req.user.id;

  const events = await getEventForCertainDate(date, userId);

  if (!events) {
    return res.json([]);
  }

  res.json(events);
});

app.get("/events", [postLimiter, verifyToken], async (req, res) => {
  const userId = req.user.id;

  const events = await getEvents(userId);

  if (!events) {
    return res.json([]);
  }

  res.json(events);
});

app.get("/events/:id", [postLimiter, verifyToken], async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  const event = await getEventById(id, userId);

  if (!event) {
    return res.json(undefined);
  }

  res.json(event);
});

app.post("/events", [postLimiter, verifyToken], async (req, res) => {
  const event = req.body;
  const userId = req.user.id;

  const id = await createEvent(event, userId);

  res.status(201).json({ id });
});

app.delete("/events/:id", [postLimiter, verifyToken], async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  const removedEvent = await removeEvent(id, userId);

  if (!removedEvent) {
    return res.status(404).json(undefined);
  }

  res.status(204).send();
});

app.put("/events/:id", [postLimiter, verifyToken], async (req, res) => {
  const { id } = req.params;

  const { name, description, location, from_date, to_date, contact } = req.body;

  if (!from_date || !to_date || !name) {
    return res.status(400).json({
      message: "Missing required fields",
    });
  }

  const eventUpdated = await updateEvent(id, {
    name,
    description,
    location,
    from_date,
    to_date,
    contact,
  });

  if (!eventUpdated) {
    return res.status(404).json(undefined);
  }

  res.sendStatus(204);
});

app.post("/send-message", [postLimiter, verifyToken], async (req, res) => {
  const { from, to, message } = req.body;

  if (!from || !to || !message) {
    return res.status(400).json({
      message: "Missing required fields",
    });
  }

  const accountSid = process.env.TWILIO_ACCOUNT_S_ID;
  const authToken = process.env.TWILIO_AUHT_TOKEN;
  const client = twilio(accountSid, authToken);

  client.messages
    .create({
      body: message,
      from,
      to,
    })
    .then((message) => {
      return res.sendStatus(200);
    })
    .catch((err) => {
      console.log(err);

      return res.sendStatus(500);
    });
});

app.use((err, req, res, next) => {
  console.error(err.stack);

  res.status(500).send("Something broke!");
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Listening on port 8080");
});
