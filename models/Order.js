const mongoose = require("mongoose");

const OrderSchema = new mongoose.Schema({
  userEmail: String,
  items: Array,
  totalAmount: Number,

  // 🔐 Security fields
  encryptedOrder: String,
  signature: String,
  qr: String,

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("Order", OrderSchema);