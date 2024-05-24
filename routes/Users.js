const express = require("express");
const router = express.Router();
const { Users } = require("../models");
const bcrypt = require("bcryptjs");
require("dotenv");

const { sign } = require("jsonwebtoken");
const { validateToken } = require("../middlewares/AuthMiddleware");

router.post("/", async (req, res) => {
  const { username, password } = req.body;
  bcrypt.hash(password, 10).then((hash) => {
    Users.create({
      username: username,
      password: hash,
    });
    res.json("SUCCESS");
  });
});
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await Users.findOne({ where: { username: username } });

  if (!user) {
    return res.json({ error: "User does not exist" });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.json({ error: "Wrong username or password" });
  }

  const accessToken = sign(
    { username: user.username, id: user.id },
    "importantsecret"
  );

  return res.json({
    token: accessToken,
    username: username,
    id: user.id,
    login: true,
  });
});

router.get("/auth", validateToken, (req, res) => {
  const newToken = sign(
    { username: req.user.username, id: req.user.id },
    "importantsecret"
  );
  res.json({
    username: req.user.username,
    id: req.user.id,
    token: newToken,
    login: true,
  });
});

router.get("/profile/:id", async (req, res) => {
  const id = req.params.id;

  const basicInfo = await Users.findByPk(id, {
    attributes: { exclude: ["password"] },
  });

  res.json(basicInfo);
});

router.put("/changepassword", validateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const user = await Users.findOne({ where: { username: req.user.username } });

  const match = await bcrypt.compare(oldPassword, user.password);
  if (!match) {
    return res.json({ error: "Wrong password entered" });
  } else {
    bcrypt.hash(newPassword, 10).then(async (hash) => {
      await Users.update(
        { password: hash },
        { where: { username: req.user.username } }
      );
      res.json("SUCCESS");
    });
  }
});

module.exports = router;
