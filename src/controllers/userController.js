import userModel from '../models/user.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
const addUser = async (req, res) => {
  try {
    const newUser = new userModel.User(req.body);
    const saveUser = await newUser.save();
    res.status(200).json(saveUser);
  } catch (err) {
    res.status(500).json(err);
  }
}

const loginUser = async (req, res) => {
  try {
    const user = await userModel.User.findOne({
      username: req.body.username
    });
    if (!user) {
      return res.status(404).json("User not found");
    }
    if(user.password !== req.body.password){
      return res.status(400).json("Wrong password");
    }
    const token = jwt.sign({ userId: user._id }, 'your_secret_key', { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });
    res.json({ message: 'Login successfully!' , token, user});
  } catch (err) {
    res.status(500).json(err);
  }
}
module.exports = {
  addUser: addUser,
  loginUser: loginUser
};