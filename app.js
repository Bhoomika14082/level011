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

// create new election page display
app.get(
  "/elections/new",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const login_admin_id = request.user.id;
    const admin = await Admin.findByPk(login_admin_id);

    response.render("newElection", {
      username: admin.name,
      csrf: request.csrfToken(),
    });
  }
);

// edit election display page
app.get(
  "/election/:id/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const login_admin_id = request.user.id;
    const election = await Election.findByPk(request.params.id);
    const admin = await Admin.findByPk(login_admin_id);

    if (login_admin_id !== election.adminID) {
      return response.render("error", {
        errorMessage: "This operation is not authorised by you.",
      });
    }

    response.render("editElection", {
      election: election,
      username: admin.name,
      csrf: request.csrfToken(),
    });
  }
);

// updating an election name
app.post(
  "/election/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const login_admin_id = request.user.id;
    const elections = await Election.findByPk(request.params.id);

    if (login_admin_id !== elections.adminID) {
      return response.render("error", {
        errorMessage: "You are not authorized to view this page",
      });
    }

    //checking validation
    if (request.body.name.trim().length === 0) {
      request.flash("error", "Election name can't be empty");
      return response.redirect(`/election/${request.params.id}/edit`);
    }
    const sameElection = await Election.findOne({
      where: {
        adminID: login_admin_id,
        name: request.body.name,
      },
    });

    if (sameElection) {
      if (sameElection.id.toString() !== request.params.id) {
        request.flash("error", "Election name already used");
        return response.redirect(`/election/${request.params.id}/edit`);
      } else {
        request.flash("error", "No changes made");
        return response.redirect(`/election/${request.params.id}/edit`);
      }
    }

    try {
      await Election.update(
        { name: request.body.name },
        { where: { id: request.params.id } }
      );
      response.redirect(`/election/${request.params.id}`);
    } catch (error) {
      console.log(error);
      return response.send(error);
    }
  }
);

// creating a new admin display page
app.post("/users", async (request, response) => {
  // validation checking
  if (request.body.email.trim().length === 0) {
    request.flash("error", "Email can't be empty");
    return response.redirect("/signup");
  }

  if (request.body.password.length === 0) {
    request.flash("error", "Password can't be empty");
    return response.redirect("/signup");
  }

  if (request.body.name.length === 0) {
    request.flash("error", "Name can't be empty");
    return response.redirect("/signup");
  }

  // check if email already exists
  const admin = await Admin.findOne({ where: { email: request.body.email } });
  if (admin) {
    request.flash("error", "Email already exists");
    return response.redirect("/signup");
  }

  //validating password
  if (request.body.password.length < 8) {
    request.flash("error", "Password must be atleast 8 characters long");
    return response.redirect("/signup");
  }
  // hasing the password using bcrypt
  const hashpwd = await bcrypt.hash(request.body.password, saltRounds);
  try {
    const user = await Admin.create({
      name: request.body.name,
      email: request.body.email,
      password: hashpwd,
    });
    request.login(user, (err) => {
      if (err) {
        console.log(err);
        response.redirect("/");
      } else {
        request.flash("success", "Sign up successful");
        response.redirect("/home");
      }
    });
  } catch (error) {
    request.flash("error", error.message);
    return response.redirect("/signup");
  }
});

// get all the questions of election
app.get(
  "/election/:id/questions",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const allQuestions = await question.findAll({
      where: { electionID: request.params.id },
    });

    return response.send(allQuestions);
  }
);

// add a question to the election
app.post(
  "/election/:id/questions/add",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const login_admin_id = request.user.id;

    const election = await Election.findByPk(request.params.id);

    if (login_admin_id !== election.adminID) {
      return response.render("error", {
        errorMessage: "You are not authorized to view this page",
      });
    }

    if (election.launched) {
      console.log("Election already launched");
      return response.render("error", {
        errorMessage:
          "You can't edit the election now, the election is already launched",
      });
    }

    // validation checking for adding a question
    if (request.body.title.trim().length === 0) {
      request.flash("error", "Question title can't be empty");
      return response.redirect(`/election/${request.params.id}`);
    }

    const sameQuestion = await question.findOne({
      where: { electionID: request.params.id, title: request.body.title },
    });
    if (sameQuestion) {
      request.flash("error", "Question title already used");
      return response.redirect(`/election/${request.params.id}`);
    }

    try {
      await question.add(
        request.body.title,
        request.body.description,
        request.params.id
      );
      response.redirect(`/election/${request.params.id}`);
    } catch (error) {
      console.log(error);
      return response.send(error);
    }
  }
);

// trying to delete the question
app.delete(
  "/election/:id/question/:questiondID",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const adminID = request.user.id;
    const election = await Election.findByPk(request.params.id);

    if (election.adminID !== adminID) {
      return response.render("error", {
        errorMessage: "You are not authorized to view this page",
      });
    }

    try {
      // deleting all the options for a  question
      await Option.destroy({
        where: { questionID: request.params.questiondID },
      });

      // delete a  question
      await question.destroy({ where: { id: request.params.questiondID } });
      return response.json({ ok: true });
    } catch (error) {
      console.log(error);
      return response.send(error);
    }
  }
);

// try to delete an option for the question
app.delete(
  "/election/:electionID/question/:questionID/option/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const adminID = request.user.id;
    const election = await Election.findByPk(request.params.electionID);

    if (election.adminID !== adminID) {
      return response.render("error", {
        errorMessage: "You are not authorized to view this page",
      });
    }

    const Question = await question.findByPk(request.params.questionID);

    if (!Question) {
      console.log("Question not found");
      return response.render("error", { errorMessage: "Question not found" });
    }

    try {
      await Option.destroy({ where: { id: request.params.id } });
      return response.json({ ok: true });
    } catch (error) {
      console.log(error);
      return response.send(error);
    }
  }
);

// questions home page with all options
app.get(
  "/election/:id/question/:questiondID",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const adminID = request.user.id;
    const admin = await Admin.findByPk(adminID);
    const election = await Election.findByPk(request.params.id);

    if (election.adminID !== adminID) {
      return response.render("error", {
        errorMessage: "This operation is not authorised by you.",
      });
    }

    const Question = await question.findByPk(request.params.questiondID);

    const options = await Option.findAll({
      where: { questionID: request.params.questiondID },
    });

    response.render("questionHome", {
      username: admin.name,
      question: Question,
      election: election,
      options: options,
      csrf: request.csrfToken(),
    });
  }
);

// adding option to the questions asked in election
app.post(
  "/election/:electionID/question/:questionID/options/add",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const adminID = request.user.id;

    const election = await Election.findByPk(request.params.electionID);

    if (election.adminID !== adminID) {
      console.log("You don't have access to edit this election");
      return response.render("error", {
        errorMessage: "You are not authorized to view this page",
      });
    }

    if (election.launched) {
      console.log("Election already launched");
      return response.render("error", {
        errorMessage: "Election is already live",
      });
    }

    // The  validation check happens here
    if (request.body.option.trim().length === 0) {
      request.flash("error", "Option can't be empty");
      return response.redirect(
        `/election/${request.params.electionID}/question/${request.params.questionID}`
      );
    }

    const sameOption = await Option.findOne({
      where: {
        questionID: request.params.questionID,
        value: request.body.option,
      },
    });
    if (sameOption) {
      request.flash("error", "Option already exists");
      return response.redirect(
        `/election/${request.params.electionID}/question/${request.params.questionID}`
      );
    }

    try {
      await Option.add(request.body.option, request.params.questionID);
      response.redirect(
        `/election/${request.params.electionID}/question/${request.params.questionID}`
      );
    } catch (error) {
      console.log(error);
      return response.send(error);
    }
  }
);

// trying to get the  options for a election
app.get(
  "/election/:electionID/question/:questionID/options",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const options = await Option.findAll({
      where: { questionID: request.params.questionID },
    });
    return response.send(options);
  }
);

module.exports = app;
