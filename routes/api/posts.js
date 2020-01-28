const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const Post = require('../../models/Post');

// @route POST api/posts
// @desc Create a post
// @access Private
router.post('/', [
    auth,
    [
        check('text', 'Text is required').not().isEmpty()
    ]], async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const user = await User.findById(req.user.id).select('-password');

            const newPost = {
                text: req.body.text,
                name: user.name,
                avatar: user.avatar,
                user: req.user.id
            }

            const post = new Post(newPost);

            await post.save();

            res.status(200).json(post);

        } catch (error) {
            console.error(error.message);
            res.status(500).send('Server error');
        }
    });

// @route GET api/posts
// @desc Get all post
// @access Private
router.get('/', async (req, res) => {
    try {
        const posts = await Post.find().sort({ date: -1 });
        res.json(posts);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
})

// @route GET api/posts
// @desc Get post by ID
// @access Private
router.get('/:id', async (req, res) => {
    try {
        const posts = await Post.findById(req.params.id);
        if (!posts) {
            return res.status(404).json({ msg: "Post not found" });
        }

        res.json(posts);
    } catch (error) {
        console.error(error.message);
        if (error.kind === 'ObjectId') {
            return res.status(404).json({ msg: 'Post not found' });
        }
        res.status(500).send('Server error');
    }
})

// @route DELETE api/posts
// @desc Delete post by ID
// @access Private
router.delete('/:id', auth, async (req, res) => {
    try {
        const posts = await Post.findById(req.params.id);
        if (!posts) {
            return res.status(404).json({ msg: "Post not found" });
        }
        // Check user
        if (posts.user.toString() !== req.user.id) {
            return res.status(401).json({ msg: "User not authorized" });
        }
        await posts.remove();
        res.json({ msg: "Post removed" });
    } catch (error) {
        console.error(error.message);
        if (error.kind === 'ObjectId') {
            return res.status(404).json({ msg: 'Post not found' });
        }
        res.status(500).send('Server error');
    }
})

// @route PUT api/posts/like/:id
// @desc Like a post
// @access Private
router.put('/like/:id', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);

        if (post.likes.filter(like => like.user.toString() === req.user.id).length > 0) {
            return res.status(400).json({ msg: 'Post already liked' });
        }

        post.likes.unshift({ user: req.user.id });

        await post.save();

        res.status(200).json(post.likes);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
})

// @route PUT api/posts/like/:id
// @desc Like a post
// @access Private
router.put('/unlike/:id', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);

        if (post.likes.filter(like => like.user.toString() === req.user.id).length === 0) {
            return res.status(400).json({ msg: "Post don't like" });
        }

        const removeIndex = post.likes.map(like => like.user.toString()).indexOf(req.user.id);

        post.likes.splice(removeIndex, 1);

        await post.save();

        res.status(200).json(post.likes);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
})

// @route POST api/posts/comment/:id
// @desc Create a comment
// @access Private
router.post('/comment/:id', [
    auth,
    [
        check('text', 'Text is required').not().isEmpty()
    ]], async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const user = await User.findById(req.user.id).select('-password');

            const post = await Post.findById(req.params.id);

            const newComment = {
                text: req.body.text,
                name: user.name,
                avatar: user.avatar,
                user: req.user.id
            }

            post.comments.unshift(newComment);

            await post.save();

            res.status(200).json(post);

        } catch (error) {
            console.error(error.message);
            res.status(500).send('Server error');
        }
    });


// @route DELETE api/posts/comment/:id/:comment_id
// @desc Delete a comment
// @access Private
router.delete('/comment/:id/:comment_id', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');

        const post = await Post.findById(req.params.id);

        const comment = post.comments.find(comment => comment.id === req.params.comment_id);

        if (!comment) {
            return res.status(404).send("Comment dose not exist");
        }

        if (comment.user.toString() !== user.id) {
            return res.status(401).send("User not authorized");
        }

        const removeIndex = post.comments.map(comment => comment.user.toString()).indexOf(user.id);

        post.comments.splice(removeIndex, 1);

        await post.save();

        res.status(200).json(post.comments);

    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
});

module.exports = router;