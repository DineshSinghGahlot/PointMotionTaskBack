const express = require("express");
const { check, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const router = express.Router();
const auth = require("../middleware/auth");
const jwt_decode = require("jwt-decode");
const fs = require("fs");

router.post(
  "/signup",
  [
    check("userName", "Please Enter a Valid Username")
      .isLength({
        min: 4,
      })
      .withMessage("User Name must be of 4 characters long.")
      .isLowercase()
      .withMessage("Must be all small letters")
      .isAlpha()
      .withMessage("User Name must be alphabetic."),
    check("firstName")
      .isLength({ min: 3 })
      .withMessage("Name must be of 3 characters long.")
      .isAlpha()
      .withMessage("Name must be alphabetic."),
    check("lastName")
      .isLength({ min: 3 })
      .withMessage("Last Name must be of 3 characters long.")
      .isAlpha()
      .withMessage("Last Name must be alphabetic."),
    check("password", "Please enter a valid password", "...")
      .isLength({
        min: 5,
      })
      .withMessage("Password must be of 5 characters long.")
      .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])/, "i")
      .withMessage(
        "Password must be must contain at least 1 uppercase character must contain at least 1 lowercase character must contain at least 1 number no special characters allowed."
      ),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
      });
    }

    const { userName, firstName, lastName, password } = req.body;
    try {
      let existingData = await fs.readFileSync("./data/user.json");
      existingData = await JSON.parse(existingData);
      const salt = await bcrypt.genSalt(10);
      let hashedPassword = await bcrypt.hash(password, salt);
      let userId = Math.floor(Math.random() * 100000);
      let user;
      await existingData.user.map((result, err) => {
        if (result.userName === req.body.userName) {
          user = result;
        }
      });

      if (user) {
        return res.status(400).json({
          msg: "User Already Exists",
        });
      }
      existingData.user.push({
        id: userId,
        userName: userName,
        firstName: firstName,
        lastName: lastName,
        password: hashedPassword,
      });

      let userData = JSON.stringify(existingData);
      await fs.writeFileSync("./data/user.json", userData);

      let token = jwt.sign({ user: userId }, "randomString", {
        expiresIn: 10000,
      });
      console.log(token);
      res.status(201).json({
        token,
        message: "SignUp success. Please proceed to Signin",
      });
    } catch (err) {
      console.log(err);
      res.status(500).send("Error in Saving");
    }
  }
);

router.post(
  "/login",
  [
    check("userName", "Please Enter a Valid Username")
      .isLength({
        min: 4,
      })
      .isLowercase()
      .withMessage("Must be all small letters")
      .isAlpha()
      .withMessage("User Name must be alphabetic."),
    check("password", "Please enter a valid password", "...")
      .isLength({
        min: 5,
      })
      .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])/, "i"),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
      });
    }
    try {
      let existingData = await fs.readFileSync("./data/user.json");
      existingData = await JSON.parse(existingData);
      let user;
      await existingData.user.map((result, err) => {
        if (result.userName === req.body.userName) {
          user = result;
        }
      });
      if (!user)
        return res.status(400).json({
          message: "User Not Exist",
        });

      const isMatch = await bcrypt.compare(req.body.password, user.password);
      if (!isMatch)
        return res.status(400).json({
          message: "Incorrect Password !",
        });

      jwt.sign(
        {
          userId: user.id,
        },
        "randomString",
        {
          expiresIn: 3600,
        },
        (err, token) => {
          if (err) throw err;
          res.status(200).json({
            token,
            message: "Signin success",
          });
        }
      );
    } catch (e) {
      console.error(e);
      res.status(500).json({
        message: "Server Error",
      });
    }
  }
);

router.get("/me", auth, async (req, res) => {
  try {
    // request.user is getting fetched from Middleware after token authentication
    const decoded = jwt_decode(req.headers.authorization.split(" ")[1]);
    let existingData = await JSON.parse(fs.readFileSync("./data/user.json"));
    let user;
    await existingData.user.map((result, err) => {
      if (result.id === decoded.userId) {
        user = result;
      }
    });
    if (!user) {
      res.json({ message: "User not found" });
    }
    console.log(decoded);
    res.status(200).json(user);
  } catch (e) {
    res.send({ message: "Error in Fetching user" });
  }
});

module.exports = router;
