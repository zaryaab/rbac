// server/routes/route.js
const express = require('express');
const router = express.Router();

const userController = require('../controllers/userController');

router.post('/signup', userController.signUp);
router.post('/login', userController.login);
router.get('/users', userController.allowIfLoggedin, userController.grantAccess('readAny', 'profile'), userController.getUsers);
router.get('/user', userController.allowIfLoggedin, userController.getUser);
router.put('/user', userController.allowIfLoggedin, userController.grantAccess('updateAny', 'profile'), userController.getUsers);
router.delete('/user', userController.allowIfLoggedin, userController.grantAccess('deleteAny', 'profile'), userController.getUsers);

module.exports = router;