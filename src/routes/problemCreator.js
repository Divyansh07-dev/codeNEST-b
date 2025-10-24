const express = require('express');

const problemRouter = express.Router();
const adminMiddleware = require("../middleware/adminMiddleware");
const {createProblem,updateProblem,deleteProblem,getProblemById,getAllProblem,solvedAllProblembyUser,submittedProblem} = require("../controllers/userProblem");
const userMiddleware = require("../middleware/userMiddleware");


// Create
problemRouter.post("/create",adminMiddleware ,createProblem);
problemRouter.put("/update/:id",adminMiddleware, updateProblem);
problemRouter.delete("/delete/:id",adminMiddleware, deleteProblem);


// 🛑 FINAL FIX: Remove userMiddleware so the problems list is public
problemRouter.get("/getAllProblem", getAllProblem);

// The remaining routes still require user authentication
problemRouter.get("/problemById/:id",userMiddleware,getProblemById);
problemRouter.get("/problemSolvedByUser",userMiddleware, solvedAllProblembyUser);
problemRouter.get("/submittedProblem/:pid",userMiddleware,submittedProblem);


module.exports = problemRouter;