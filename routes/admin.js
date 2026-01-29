const express = require("express");
const Product = require("../models/Product");
const Order = require("../models/Order");
const jwt = require("jsonwebtoken");

const router = express.Router();

// Middleware: check admin
const isAdmin = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: "No token" });

  const decoded = jwt.verify(token, "SECRETKEY");
  if (decoded.role !== "admin") {
    return res.status(403).json({ message: "Admin only" });
  }
  next();
};

// ADD PRODUCT
router.post("/add-product", isAdmin, async (req, res) => {
  const product = new Product(req.body);
  await product.save();
  res.json({ message: "Product added", product });
});

// UPDATE PRODUCT
router.put("/update-product/:id", isAdmin, async (req, res) => {
  const updated = await Product.findByIdAndUpdate(
    req.params.id,
    req.body,
    { new: true }
  );
  res.json(updated);
});

// DELETE PRODUCT
router.delete("/delete-product/:id", isAdmin, async (req, res) => {
  await Product.findByIdAndDelete(req.params.id);
  res.json({ message: "Product deleted" });
});

// VIEW ALL ORDERS
router.get("/orders", isAdmin, async (req, res) => {
  const orders = await Order.find();
  res.json(orders);
});

module.exports = router;
