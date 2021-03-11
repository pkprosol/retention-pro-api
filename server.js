const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const app = express();
require("dotenv").config(); // This takes variables from your .env file, so you can store secrets, passwords, etc., for development
const fetch = require("node-fetch");
const bcrypt = require("bcrypt");

// CORS is a security thing: https://en.wikipedia.org/wiki/Cross-origin_resource_sharing
app.use(cors());
// Read up on express servers: http://expressjs.com
app.use(express.json());

const getUsers = async () =>
  fetch(
    "https://api.sheety.co/e9fa6948f6ac04d24b8e770c44de7346/retentionProDb/users",
    {
      method: "GET",
      headers: { Authorization: "Bearer " + process.env.SHEETY_TOKEN },
    }
  ).then((response) => response.json().then((json) => json));

const makeUser = (user) => {
  console.log("User to make: ", user);
  let url =
    "https://api.sheety.co/e9fa6948f6ac04d24b8e770c44de7346/retentionProDb/users";

  let body = {
    user,
  };

  fetch(url, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + process.env.SHEETY_TOKEN,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  })
    .then((response) => response.json())
    .then((json) => {
      // Do something with object
      console.log(json.user);
    });
};

const getContacts = () => {
  let url =
    "https://api.sheety.co/e9fa6948f6ac04d24b8e770c44de7346/retentionProDb/contacts";

  return fetch(url, {
    headers: { Authorization: "Bearer " + process.env.SHEETY_TOKEN }, // Stuff in process.env exists in an .env file or in Heroku config variables
  }).then((response) => response.json());
};

// This creates the access token which is used to ensure logged in users are valid
// Learn about JWT authentication here: https://www.digitalocean.com/community/tutorials/nodejs-jwt-expressjs

// Email is in the following structure: { email: "email@example.com" }
function generateAccessToken(email) {
  // expires in 48 hours
  return jwt.sign(email, process.env.TOKEN_SECRET, { expiresIn: "48h" });
}

// This checks the token on any endpoint where authenticateToken is used
function authenticateToken(req, res, next) {
  // Gather the jwt access token from the request header
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401); // if there isn't any token

  jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
    console.log(err);
    if (err) return res.sendStatus(403);
    req.user = user;
    next(); // pass the execution off to whatever request the client intended
  });
}

// Don't authenticateToken here because users logging in are non-authenticated by definition, so they won't have a token yet
// This combines signup and login into one endpoint, and figures out which one to do
app.use("/login", async (req, res) => {
  // The email and password are passed in with the request
  const { name, email, password } = req.body;

  if (!email || !password) {
    // If there's no email and password, send an error code (404 not found)
    return res.status(404).send();
  } else {
    const { users } = await getUsers();

    // Format email to be lowercase and without white space, to avoid case sensitive matching issues
    const formattedEmail = email.toLowerCase().trim();

    // Find matching user based on email
    const matchingUser = users.find((u) => u.email === formattedEmail);

    // If a user matches, log them in
    if (matchingUser) {
      // If the user is already in the database, the last step is to check the password, also using bcrypt: https://www.npmjs.com/package/bcrypt
      // What this does is compares the text password to a hashed password, which is transformed according to a complex algorithm
      // It's a one way thing, bcrypt can check that it matches, but you can't derive the original password from looking at the encrypted password

      bcrypt
        .compare(password, matchingUser.password)
        .then((valid) => {
          if (!valid) {
            return res.status(401).json({
              error: new Error("Incorrect password!"),
            });
          }

          // If it's valid we're all good, create a token and send it
          const token = generateAccessToken({ email });

          return res.status(200).json({
            userId: matchingUser.id,
            token,
          });
        })
        .catch((error) => {
          // Send any other errors that may come up
          return res.status(500).json({
            error: error,
          });
        });

      // This structure, where a variable is in brackets like so '{ email }' means it's the key and value, so this is { email: [the email value] }
    } else {
      // Do not store passwords as plain text, use bcrypt to encrypt them: https://www.npmjs.com/package/bcrypt
      const hashedPassword = await bcrypt.hash(password, 10);

      // Otherwise sign them up
      await makeUser({
        name,
        email,
        password: hashedPassword,
      });

      // Send a token either way
      const token = generateAccessToken({ email });
      return res.send({ token });
    }
  }
});

// Used one time to create a secret (it creates a different one every time)
app.use("/getTokenSecret", async (req, res) => {
  const secret = require("crypto").randomBytes(64).toString("hex");

  res.send(secret);
});

// authenticateToken Runs authentication where needed; you don't want everyone to have access to contacts
app.use("/getContacts", authenticateToken, async (req, res) => {
  const contacts = await getContacts();

  res.send(contacts);
});

app.use("/hello", async (req, res) => {
  res.send("Hello");
});

app.listen(8080, () => console.log("API is running on http://localhost:8080"));
