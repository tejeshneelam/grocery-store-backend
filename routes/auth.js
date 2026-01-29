const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const User = require("../models/User");
const Otp = require("../models/Otp");

const router = express.Router();

const ADMIN_EMAILS = [
  "admin@gmail.com",
];

/* ================= EMAIL TRANSPORT ================= */
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "nnntejesh@gmail.com",       // 🔁 replace
    pass: "jbpe ronq dopo lnfe"           // 🔁 replace
  }
});

/* ================= REGISTER ================= */
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hash });
    await user.save();

    res.status(200).json({ message: "Registered successfully" });
  } catch (err) {
    console.log("Register error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ================= LOGIN (SEND OTP) ================= */
router.post("/login", async (req, res) => {
  try {
    const { email, password, role } = req.body; // role: 'admin' or 'user'

    // If role is admin, only allow the specific admin credentials
    if (role === "admin") {
      if (email !== "admin@gmail.com") {
        return res.status(403).json({ message: "Not allowed for admin; please sign in as user" });
      }

      if (password !== "admin123") {
        return res.status(400).json({ message: "Wrong admin password" });
      }

      // Ensure an admin user exists (create if missing) and set role
      let adminUser = await User.findOne({ email });
      if (!adminUser) {
        const hash = await bcrypt.hash("admin123", 10);
        adminUser = new User({ name: "Admin", email, password: hash, role: "admin" });
        await adminUser.save();
      } else {
        // Ensure role is admin
        if (adminUser.role !== "admin") {
          adminUser.role = "admin";
          await adminUser.save();
        }
      }

      // For admin login: bypass OTP and return token immediately (admin email/password enforced)
      const token = jwt.sign(
        { id: adminUser._id, role: "admin", email: adminUser.email },
        "SECRETKEY",
        { expiresIn: "2h" }
      );

      return res.json({ token, role: "admin", email: adminUser.email });
    }

    // Default/user login flow
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: "Wrong password" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await Otp.create({
      email,
      otp,
      role: role === "admin" ? "admin" : "user",
      expiresAt: new Date(Date.now() + 5 * 60000)
    });

    /* ===== SEND OTP VIA EMAIL ===== */
    await transporter.sendMail({
      from: "Secure Grocery Shop",
      to: email,
      subject: "Your Login OTP",
      text: `Your OTP is: ${otp}. It is valid for 5 minutes.`
    });

    res.json({ message: "OTP sent to email" });
  } catch (err) {
    console.log("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ================= VERIFY OTP ================= */
router.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const record = await Otp.findOne({ email, otp });
    if (!record) return res.status(400).json({ message: "Invalid OTP" });

    if (record.expiresAt < new Date())
      return res.status(400).json({ message: "OTP expired" });

    const user = await User.findOne({ email });

    // Decide role from OTP record if provided, otherwise fallback
    const role = record.role ? record.role : (ADMIN_EMAILS.includes(email) ? "admin" : "user");

    if (!user) {
      // create minimal user if not exists (shouldn't normally happen for user flow)
      const hash = await bcrypt.hash("", 1).catch(() => "");
      const newUser = new User({ name: "User", email, password: hash, role });
      await newUser.save();
    } else {
      user.role = role;
      await user.save();
    }

    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email },
      "SECRETKEY",
      { expiresIn: "2h" }
    );

    res.json({ token, role, email });
  } catch (err) {
    console.log("Verify OTP error:", err);
    res.status(500).json({ message: "Server error" });
  }
});
// GET PROFILE
router.get("/me", async (req, res) => {
  try {
    const token = req.headers.authorization;
    const decoded = jwt.verify(token, "SECRETKEY");

    const user = await User.findById(decoded.id).select("-password");
    res.json(user);
  } catch (err) {
    res.status(401).json({ message: "Unauthorized" });
  }
});

// UPDATE PROFILE
router.put("/me", async (req, res) => {
  try {
    const token = req.headers.authorization;
    const decoded = jwt.verify(token, "SECRETKEY");

    const updated = await User.findByIdAndUpdate(
      decoded.id,
      req.body,
      { new: true }
    ).select("-password");

    res.json(updated);
  } catch (err) {
    res.status(500).json({ message: "Update failed" });
  }
});

module.exports = router;