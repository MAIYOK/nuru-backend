const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  role: String
});

const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  name: String,
  description: String,
  value: String
});

const Product = mongoose.model('Product', productSchema);

const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('Token required');
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send('Invalid token');
    req.user = decoded;
    next();
  });
};

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).send('User not found');
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).send('Invalid password');
  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET);
  res.json({ token, role: user.role });
});

app.get('/api/products', async (req, res) => {
  const products = await Product.find();
  res.json(products);
});

app.post('/api/products', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Admins only');
  const product = new Product(req.body);
  await product.save();
  res.status(201).send('Product created');
});

app.put('/api/products/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Admins only');
  await Product.findByIdAndUpdate(req.params.id, req.body);
  res.send('Product updated');
});

app.delete('/api/products/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Admins only');
  await Product.findByIdAndDelete(req.params.id);
  res.send('Product deleted');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));