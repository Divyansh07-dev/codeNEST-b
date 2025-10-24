const express = require('express');
const submitRouter = express.Router();
const userMiddleware = require("../middleware/userMiddleware");

// Ensure all exported functions are imported
const {submitCode,runCode, getSubmissionHistory} = require("../controllers/userSubmission"); 

submitRouter.post("/submit/:id", userMiddleware, submitCode);
submitRouter.post("/run/:id",userMiddleware,runCode);

// ⭐ NEW ROUTE: For fetching the submission history (the "Submissions" tab)
submitRouter.get("/history/:id", userMiddleware, getSubmissionHistory);

module.exports = submitRouter;