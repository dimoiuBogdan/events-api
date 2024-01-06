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
import { createClient } from "redis";
import serverless from "serverless-http";

dotenv.config();

const app = express();
const router = express.Router();

app.use(cors());
app.use(express.json());

const redisClient = createClient({
  password: process.env.REDIS_PASSWORD,
  socket: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
});

await redisClient.connect();

const database = mysql.createConnection(process.env.PS_DATABASE_HOST).promise();

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

router.post(
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

router.get("/get-profile-image/:userId", async (req, res) => {
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

const addRefreshTokenToRedis = async (refreshToken) => {
  await redisClient.sAdd("refreshTokens", refreshToken);
};

const removeRefreshTokenFromRedis = async (refreshToken) => {
  await redisClient.sRem("refreshTokens", refreshToken);
};

const refreshTokenExistsInRedis = async (refreshToken) => {
  return await redisClient.sIsMember("refreshTokens", refreshToken);
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

router.post("/users/register", secureLimiter, async (req, res) => {
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

router.post("/users/login", secureLimiter, async (req, res) => {
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

  addRefreshTokenToRedis(refreshToken);

  res.json({ id: user.id, email: user.email, accessToken, refreshToken });
});

router.post("/users/logout", verifyToken, (req, res) => {
  const { refreshToken } = req.body;

  removeRefreshTokenFromRedis(refreshToken);

  res.status(200).json({ message: "Logged out successfully" });
});

router.post("/users/refresh", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({
      message: "You are not authenticated",
    });
  }

  if (!refreshTokenExistsInRedis(refreshToken)) {
    return res.status(403).json({
      message: "Invalid refresh token",
    });
  }

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        message: "Invalid refresh token",
      });
    }

    removeRefreshTokenFromRedis(refreshToken);

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    addRefreshTokenToRedis(newRefreshToken);

    res
      .status(200)
      .json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  });
});

router.get("/users/:id", verifyToken, async (req, res) => {
  const { id } = req.params;

  const user = await getUserById(id);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  res.json(user);
});

router.patch("/users/:id", [postLimiter, verifyToken], async (req, res) => {
  const { id } = req.params;

  const { key, value } = req.body;

  const updated = await updateUserData(id, value, key);

  if (!updated) {
    return res.status(404).json({ message: "User not found" });
  }

  res.sendStatus(204);
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

router.get("/events/date", [postLimiter, verifyToken], async (req, res) => {
  const { date } = req.query;
  const userId = req.user.id;

  const events = await getEventForCertainDate(date, userId);

  if (!events) {
    return res.json([]);
  }

  res.json(events);
});

router.get("/events", [postLimiter, verifyToken], async (req, res) => {
  const userId = req.user.id;

  const events = await getEvents(userId);

  if (!events) {
    return res.json([]);
  }

  res.json(events);
});

router.get("/events/:id", [postLimiter, verifyToken], async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  const event = await getEventById(id, userId);

  if (!event) {
    return res.json(undefined);
  }

  res.json(event);
});

router.post("/events", [postLimiter, verifyToken], async (req, res) => {
  const event = req.body;
  const userId = req.user.id;

  const id = await createEvent(event, userId);

  res.status(201).json({ id });
});

router.delete("/events/:id", [postLimiter, verifyToken], async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  const removedEvent = await removeEvent(id, userId);

  if (!removedEvent) {
    return res.status(404).json(undefined);
  }

  res.status(204).send();
});

router.put("/events/:id", [postLimiter, verifyToken], async (req, res) => {
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

router.post("/send-message", [postLimiter, verifyToken], async (req, res) => {
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

app.use("/api", router);

app.listen(8080, () => {
  console.log("Listening on port 8080");
});

export const handler = serverless(app);
