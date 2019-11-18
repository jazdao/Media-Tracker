// middleware.js
const functions = require('firebase-functions');
const jwt = require('jsonwebtoken');

const secret = functions.config().mt.mongo_secret;
//const secret = process.env.mongo_secret;

const withAuth = function (req, res, next) {
    const token =
        req.query.token ||
        req.headers['x-access-token'] ||
        req.cookies.token;
    if (!token) {
        res.status(401).send('Unauthorized: No token provided');
    } else {
        jwt.verify(token, secret, function (err, decoded) {
            if (err) {
                res.status(401).send('Unauthorized: Invalid token');
            } else {
                req.email = decoded.email;
                next();
            }
        });
    }
}

module.exports = withAuth;