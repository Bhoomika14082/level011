/* eslint-disable no-undef */
const request = require("supertest");
const cheerio = require("cheerio");
const db = require("../models/index");
const app = require("../app");

let server, agent;

function extractCsrfToken(res) {
  var $ = cheerio.load(res.text);
  return $("[name=_csrf]").val();
}

const login = async () => {
  await agent
    .post("/session")
    .send({ email: "test@user.com", password: "1234567890" });
};

describe("Test cases", () => {
  beforeAll(async () => {
    await db.sequelize.sync({ force: true });
    server = app.listen(6000, () => {});
    agent = request.agent(server);
  });

  afterAll(async () => {
    await db.sequelize.close();
    server.close();
  });

  test("First case", () => {
    expect(1).toBe(1);
  });

  test("User login(admin)", async () => {
    const res = await agent.get("/home");
    expect(res.statusCode).toBe(302);
  });

  test("Admin authentication page works", async () => {
    const res = await agent.get("/signup");
    expect(res.statusCode).toBe(200);
    const login = await agent.get("/login");
    expect(login.statusCode).toBe(200);
  });

  test("Signup new user(admin)", async () => {
    const signupPage = await agent.get("/signup");
    const token = extractCsrfToken(signupPage);
    const res = await agent.post("/users").send({
      name: "admin",
      email: "test@user.com",
      password: "1234567890",
      _csrf: token,
    });
    expect(res.statusCode).toBe(302);
  });

  test("Creating election", async () => {
    let count, newCount;
    const addElection = await agent.get("/elections/new");
    const token = extractCsrfToken(addElection);
    const response = await agent.get("/election");
    count = response.body.elections.length;

    await agent.post("/election").send({
      name: "Election-22",
      _csrf: token,
    });

    await agent.get("/election").then((data) => {
      newCount = data.body.elections.length;
    });
    expect(newCount).toBe(count + 1);
  });

  test("End election", async () => {
    let count, newCount;
    const addElection = await agent.get("/elections/new");
    const token = extractCsrfToken(addElection);
    const response = await agent.get("/election");
    count = response.body.elections.length;

    const electionID = response.body.elections[count - 1].id;

    await agent.post("/election").send({
      name: "test election launch",
      _csrf: token,
    });

    await agent.get("/election").then((data) => {
      newCount = data.body.elections.length;
    });
    expect(newCount).toBe(count + 1);

    const res2 = await agent.get(`/election/${electionID}`);
    const token2 = extractCsrfToken(res2);

    const result2 = await agent.get(`/election/${electionID}/launch`).send({
      _csrf: token2,
    });

    expect(result2.statusCode).toBe(302);

    const res = await agent.get(`/election/${electionID}`);
    const token3 = extractCsrfToken(res);

    const result = await agent.put(`/election/${electionID}/end`).send({
      _csrf: token3,
    });

    expect(result.ok).toBe(true);
  });

  test("Delete election", async () => {
    let count;
    const response = await agent.get("/election");
    count = response.body.elections.length;

    const electionID = response.body.elections[count - 1].id;

    const electionPage = await agent.get(`/election/${electionID}`);
    const token = extractCsrfToken(electionPage);
    const res = await agent.delete(`/election/${electionID}`).send({
      _csrf: token,
    });

    expect(res.ok).toBe(true);
  });

  test("Edit election", async () => {
    const res = await agent.get("/elections/new");
    const token = extractCsrfToken(res);
    await agent.post("/election").send({
      name: "update election",
      _csrf: token,
    });
    let count;
    let response = await agent.get("/election");
    count = response.body.elections.length;

    const electionID = response.body.elections[count - 1].id;

    const electionPage = await agent.get(`/election/${electionID}`);
    const newToken = extractCsrfToken(electionPage);
    await agent
      .post(`/election/${electionID}`)
      .send({ name: "Election 1", _csrf: newToken });

    response = await agent.get("/election");
    expect(response.body.elections[count - 1].name).toBe("Election 1");
  });

  test("Add question", async () => {
    let count;
    const response = await agent.get("/election");
    count = response.body.elections.length;

    const electionID = response.body.elections[count - 1].id;
    const res = await agent.get(`/election/${electionID}`);
    const token = extractCsrfToken(res);

    const result = await agent
      .post(`/election/${electionID}/questions/add`)
      .send({
        title: "Question 1",
        description: "This is description",
        _csrf: token,
      });

    expect(result.statusCode).toBe(302);
  });

  test("Edit question", async () => {
    let count;
    const response = await agent.get("/election");
    count = response.body.elections.length;

    const electionID = response.body.elections[count - 1].id;

    const questions = await agent.get(`/election/${electionID}/questions`);
    const questionID = questions._body[0].id;

    const res = await agent.get(`/election/${electionID}`);
    const token = extractCsrfToken(res);

    const result = await agent
      .post(`/election/${electionID}/question/${questionID}/update`)
      .send({
        title: "Question 1",
        description: "This is edited description",
        _csrf: token,
      });

    expect(result.statusCode).toBe(302);
  });

  test("Delete question", async () => {
    let count;
    const response = await agent.get("/election");
    count = response.body.elections.length;

    const electionID = response.body.elections[count - 1].id;

    const addRes = await agent.get(`/election/${electionID}`);
    const addToken = extractCsrfToken(addRes);

    await agent.post(`/election/${electionID}/questions/add`).send({
      title: "Question 3",
      description: "This is description",
      _csrf: addToken,
    });

    const questions = await agent.get(`/election/${electionID}/questions`);
    const questionID = questions._body[0].id;

    const res = await agent.get(`/election/${electionID}`);
    const token = extractCsrfToken(res);

    const result = await agent
      .delete(`/election/${electionID}/question/${questionID}`)
      .send({
        _csrf: token,
      });

    expect(result.statusCode).toBe(200);
  });

  test("Adding option to question", async () => {
    let count;
    const response = await agent.get("/election");
    count = response.body.elections.length;

    const electionID = response.body.elections[count - 1].id;

    const questions = await agent.get(`/election/${electionID}/questions`);
    const questionID = questions._body[0].id;

    const res = await agent.get(`/election/${electionID}`);
    const token = extractCsrfToken(res);

    const result = await agent
      .post(`/election/${electionID}/question/${questionID}/options/add`)
      .send({
        option: "Option 1",
        _csrf: token,
      });

    // adding 2nd option
    const res2 = await agent.get(`/election/${electionID}`);
    const token2 = extractCsrfToken(res2);

    await agent
      .post(`/election/${electionID}/question/${questionID}/options/add`)
      .send({
        option: "Option 1",
        _csrf: token2,
      });

    expect(result.statusCode).toBe(302);
  });

  test("Edit options", async () => {
    let count;
    const response = await agent.get("/election");
    count = response.body.elections.length;

    const electionID = response.body.elections[count - 1].id;

    const questions = await agent.get(`/election/${electionID}/questions`);
    const questionCount = questions._body.length;
    const questionID = questions._body[questionCount - 1].id;

    const optionsRes = await agent.get(
      `/election/${electionID}/question/${questionID}/options`
    );
    const options = optionsRes._body;
    const optionCount = options.length;
    const optionID = options[optionCount - 1].id;

    const res2 = await agent.get(
      `/election/${electionID}/question/${questionID}/option/${optionID}/edit`
    );
    const token2 = extractCsrfToken(res2);

    const updateRes = await agent
      .post(
        `/election/${electionID}/question/${questionID}/option/${optionID}/update`
      )
      .send({
        value: "Edited New Option 1",
        _csrf: token2,
      });

    expect(updateRes.statusCode).toBe(302);
  });

  test("Delete option", async () => {
    let count;
    const response = await agent.get("/election");
    count = response.body.elections.length;

    const electionID = response.body.elections[count - 1].id;

    const questions = await agent.get(`/election/${electionID}/questions`);
    const questionID = questions._body[0].id;

    const res2 = await agent.get(`/election/${electionID}`);
    const token2 = extractCsrfToken(res2);

    await agent
      .post(`/election/${electionID}/question/${questionID}/options/add`)
      .send({
        option: "Option 1",
        _csrf: token2,
      });

    const res = await agent.get(`/election/${electionID}`);
    const token = extractCsrfToken(res);

    const result = await agent
      .delete(`/election/${electionID}/question/${questionID}/option/1`)
      .send({
        _csrf: token,
      });

    expect(result.statusCode).toBe(200);
  });

  test("signout admin", async () => {
    login();
    await agent.get("/signout");
    const res = await agent.get("/home");
    expect(res.statusCode).toBe(302);
  });
});
