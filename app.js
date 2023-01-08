/* eslint-disable no-undef */
const express = require("express");
const app = express();
const path = require("path");
const { Admin, Option, Election, Voter, question } = require("./models");
const bcrypt = require("bcrypt");
var cookieParser = require("cookie-parser");

const connectEnsureLogin = require("connect-ensure-login");
const session = require("express-session");
const localStrategy = require("passport-local");
const passport = require("passport");
const flash = require("connect-flash");
const csrf = require("tiny-csrf");

const saltRounds = 10;

const bodyParser = require("body-parser");

app.use(flash());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser("ssh! some secret string!"));
app.use(csrf("this_should_be_32_character_long", ["POST", "PUT", "DELETE"]));

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "my-super-secret-key-3429834092402",
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

app.use(function (request, response, next) {
  response.locals.messages = request.flash();
  next();
});

//initializing passport
app.use(passport.initialize());

//using passport session
app.use(passport.session());

//passport session for admin
passport.use(
  "admin",
  new localStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    (username, password, done) => {
      Admin.findOne({ where: { email: username } })
        .then(async (user) => {
          const result = await bcrypt.compare(password, user.password);
          if (result) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Invalid password" });
          }
        })
        .catch((error) => {
          console.log(error);
          return done(null, false, {
            message: "Email is not registered!!Please  Register",
          });
        });
    }
  )
);

// passport session for voter
passport.use(
  "voter",
  new localStrategy(
    {
      usernameField: "voterID",
      passwordField: "password",
      passReqToCallback: true,
    },
    (request, username, password, done) => {
      Voter.findOne({
        where: { voterID: username, electionID: request.params.id },
      })
        .then(async (voter) => {
          const result = await bcrypt.compare(password, voter.password);
          if (result) {
            return done(null, voter);
          } else {
            return done(null, false, { message: "Invalid password" });
          }
        })
        .catch((error) => {
          console.log(error);
          return done(null, false, {
            message: "Voter is not registered!!",
          });
        });
    }
  )
);

//serializing user using passport
passport.serializeUser((user, done) => {
  done(null, user);
});

//deserializing user using passport
passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// landup page
app.get("/", (request, response) => {
  response.render("home");
});

// login page frontend
app.get("/login", (request, response) => {
  if (request.user && request.user.id) {
    return response.redirect("/home");
  }
  response.render("login", { csrf: request.csrfToken() });
});

// signup page
app.get("/signup", (request, response) => {
  response.render("signup", { csrf: request.csrfToken() });
});

//retreive all elections using loggedinId
app.get(
  "/election",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const login_admin_id = request.user.id;
    const elections = await Election.findAll({
      where: { adminID: login_admin_id },
    });

    return response.json({ elections });
  }
);

// admin home page
app.get(
  "/home",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const login_admin_id = request.user.id;
    const admin = await Admin.findByPk(login_admin_id);

    const elections = await Election.findAll({
      where: { adminID: request.user.id },
    });

    const username = admin.name;

    response.render("adminHome", {
      username: username,
      ad_id: login_admin_id,
      elections: elections,
      csrf: request.csrfToken(),
    });
  }
);

// election home page
app.get(
  "/election/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const login_admin_id = request.user.id;
    const admin = await Admin.findByPk(login_admin_id);

    username = admin.name;
    const elections = await Election.findByPk(request.params.id);

    if (login_admin_id !== elections.adminID) {
      return response.render("error", {
        errorMessage: "You are not authorized to view this page",
      });
    }

    const questions = await question.findAll({
      where: { electionID: request.params.id },
    });

    const voters = await Voter.findAll({
      where: { electionID: request.params.id },
    });

    response.render("electionHome", {
      election: elections,
      username: username,
      questions: questions,
      voters: voters,
      csrf: request.csrfToken(),
    });
  }
);

// trying to delete an election with id
app.delete(
  "/election/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const adminID = request.user.id;
    const election = await Election.findByPk(request.params.id);

    if (adminID !== election.adminID) {
      console.log("You are not authorized to perform this operation");
      return response.redirect("/home");
    }

    // get all questions of that election
    const questions = await question.findAll({
      where: { electionID: request.params.id },
    });

    // delete all options and then questions of that election
    questions.forEach(async (Question) => {
      const options = await Option.findAll({
        where: { questionID: Question.id },
      });
      options.forEach(async (option) => {
        await Option.destroy({ where: { id: option.id } });
      });
      await question.destroy({ where: { id: Question.id } });
    });

    // delete voters of the election
    const voters = await Voter.findAll({
      where: { electionID: request.params.id },
    });
    voters.forEach(async (voter) => {
      await Voter.destroy({ where: { id: voter.id } });
    });

    try {
      await Election.destroy({ where: { id: request.params.id } });
      return response.json({ ok: true });
    } catch (error) {
      console.log(error);
      response.send(error);
    }
  }
);

// creating a new election
app.post(
  "/election",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.body.name.trim().length === 0) {
      request.flash("error", "Election name can't be empty");
      return response.redirect("/elections/new");
    }

    const login_admin_id = request.user.id;

    // validation checks
    const election = await Election.findOne({
      where: { adminID: login_admin_id, name: request.body.name },
    });
    if (election) {
      request.flash("error", "Election name already used");
      return response.redirect("/elections/new");
    }

    try {
      await Election.add(login_admin_id, request.body.name);
      response.redirect("/home");
    } catch (error) {
      console.log(error);
      response.send(error);
    }
  }
);
module.exports = app;
