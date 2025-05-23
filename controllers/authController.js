const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');
const appleSignin = require('apple-signin-auth');
const User = require('../models/User');

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const generateToken = (user) => jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });

exports.register = async (req, res) => {
  const { email, username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);
  const user = new User({ email, username, password: hashedPassword });
  await user.save();
  res.status(201).send({ token: generateToken(user), user });
};

exports.login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).send({ error: 'Invalid credentials' });
  res.send({ token: generateToken(user), user });
};

exports.logout = (req, res) => {
  res.send({ message: 'Logged out' });
};

exports.getMe = async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).send({ error: 'No token' });
  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    res.send(user);
  } catch (err) {
    res.status(401).send({ error: 'Invalid token' });
  }
};

exports.googleAuth = async (req, res) => {
  try {
    const { token } = req.body;
    const ticket = await googleClient.verifyIdToken({ idToken: token, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    let user = await User.findOne({ email: payload.email });
    if (!user) {
      user = new User({ email: payload.email, username: payload.name, password: '' });
      await user.save();
    }
    res.send({ token: generateToken(user), user });
  } catch (err) {
    res.status(401).send({ error: 'Google authentication failed' });
  }
};

exports.appleAuth = async (req, res) => {
  try {
    const { identityToken } = req.body;
    const appleUser = await appleSignin.verifyIdToken(identityToken, {
      audience: process.env.APPLE_CLIENT_ID,
      ignoreExpiration: true,
    });
    let user = await User.findOne({ email: appleUser.email });
    if (!user) {
      user = new User({ email: appleUser.email, username: appleUser.email.split('@')[0], password: '' });
      await user.save();
    }
    res.send({ token: generateToken(user), user });
  } catch (err) {
    res.status(401).send({ error: 'Apple authentication failed' });
  }
};
