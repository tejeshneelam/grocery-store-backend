const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const authRoutes = require("./routes/auth");
const orderRoutes = require("./routes/order");
const adminRoutes = require("./routes/admin");
const productRoutes = require("./routes/products");

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI || "mongodb+srv://nnntejesh_db_user:b7putMQaUEBKV7pU@cluster-groecery.icnthc3.mongodb.net/")
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

app.get("/", (req, res) => {
  res.send("Backend running");
});

app.use("/api/auth", authRoutes);
app.use("/api/order", orderRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/products", productRoutes);


const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

