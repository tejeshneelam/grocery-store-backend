const mongoose = require("mongoose");

const ProductSchema = new mongoose.Schema({
  name: String,
  price: Number,
  quantity: Number,
  image: String,
  category: String   // 🔥 new
});

module.exports = mongoose.model("Product", ProductSchema);
