import jwt from 'jsonwebtoken';
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
      return res.redirect('/api/user/login');
    }
  
    jwt.verify(token, 'your_secret_key', (err, user) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid Token ' });
      }
  
      req.user = user;
      next();
    });
};

export default authenticateToken;
