const express = require("express");
const crypto = require("crypto");
const QRCode = require("qrcode");
const jwt = require("jsonwebtoken");
const Order = require("../models/Order");

const router = express.Router();

// RSA keys (demo)
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

router.post("/place", async (req, res) => {
  try {
    const token = req.headers.authorization;
    const decoded = jwt.verify(token, "SECRETKEY");

    const { items, totalAmount } = req.body;
    const userEmail = decoded.email;

    /* ================= SAVE TO DATABASE ================= */
    const orderDoc = new Order({
      userEmail,
      items,
      totalAmount
    });

    await orderDoc.save();

    /* ================= LAB CRYPTO PART ================= */
    const orderPayload = JSON.stringify({
      orderId: orderDoc._id,
      user: userEmail,
      items,
      totalAmount
    });

    // AES Encryption
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
    let encrypted = cipher.update(orderPayload, "utf8", "hex");
    encrypted += cipher.final("hex");

    // RSA Digital Signature
    const sign = crypto.createSign("SHA256");
    sign.update(orderPayload);
    const signature = sign.sign(privateKey, "hex");

    // QR Encoding
    const qr = await QRCode.toDataURL(orderDoc._id.toString());

    /* ================= UPDATE ORDER WITH SECURITY DATA ================= */
    orderDoc.encryptedOrder = encrypted;
    orderDoc.signature = signature;
    orderDoc.qr = qr;
    await orderDoc.save();

    res.json({
      message: "Order placed securely",
      orderId: orderDoc._id,
      encryptedOrder: encrypted,
      signature,
      qr
    });

  } catch (err) {
    console.log("ORDER ERROR:", err);
    res.status(500).json({ message: "Order failed" });
  }
});

module.exports = router;