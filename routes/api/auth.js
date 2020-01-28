const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');


// @route GET api/auth
// @desc Auth route
// @access Public
router.get('/', auth, async (req, res) => {
    const token = req.header('x-auth-token');

    if (!token) {
        res.status(400).send('Token is invalid');
    }

    const decoded = await jwt.verify(token, config.get('jwtSecret'));

    const user = await User.findById(decoded.user.id).select('-password');

    res.status(200).send(user);
})

// @route POST api/auth
// @desc Login
// @access Public
router.post('/', [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists(),
], async (req, res) => {
    const errors = validationResult(req);
    console.log(errors);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        // See if user exits
        let user = await User.findOne({ email });

        if (!user) {
            res.status(400).json({ errors: [{ msg: "Invalid Credentials" }] })
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: [{ msg: "Invalid credentials" }] });
        }
        // Return jsonwebtoken
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(payload, config.get('jwtSecret'),
            { expiresIn: 360000 },
            (error, token) => {
                if (error) throw error;
                res.json({ token });
            }
        )
    } catch (errors) {
        console.error(errors.message);
        res.status(500).send('Server error');
    }
});

module.exports = router;