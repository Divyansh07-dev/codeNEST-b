const Problem = require("../models/problem");
const Submission = require("../models/submission");
const User = require("../models/user");
const {getLanguageById,submitBatch,submitToken} = require("../utils/problemUtility");

// NOTE: If your function is named 'submittedProblem' in your traceback, 
// you must rename 'submitCode' to 'submittedProblem' here AND in the router.
const submitCode = async (req,res)=>{
    
    try{
        
        const userId = req.result._id;
        const problemId = req.params.id;

        let {code,language} = req.body;

        // Validation and early exit
        if(!userId||!code||!problemId||!language)
          return res.status(400).send("Some field missing");
        
        if(language==='cpp')
          language='c++'
        
        // Fetch the problem
        const problem = await Problem.findById(problemId);
        
        if (!problem) {
            return res.status(404).send("Problem not found");
        }
        
        // 1. Create Submission (Status: pending)
        const submittedResult = await Submission.create({
            userId,
            problemId,
            code,
            language,
            status:'pending',
            testCasesTotal:problem.hiddenTestCases.length
        });

        // 2. Prepare and Send to Judge0
        const languageId = getLanguageById(language);
        
        const submissions = problem.hiddenTestCases.map((testcase)=>({
            source_code:code,
            language_id: languageId,
            stdin: testcase.input,
            expected_output: testcase.output
        }));

        const submitResult = await submitBatch(submissions);
        const resultToken = submitResult.map((value)=> value.token);
        const testResult = await submitToken(resultToken);
        
        
        // 3. Process Results
        let testCasesPassed = 0;
        let runtime = 0;
        let memory = 0;
        let status = 'accepted';
        let errorMessage = null;

        for(const test of testResult){
            if(test.status_id==3){ // Accepted
               testCasesPassed++;
               runtime = runtime+parseFloat(test.time) 
               memory = Math.max(memory,test.memory);
            }else{
              if(test.status_id==4){ // Compilation/Runtime Error
                 status = 'error'
                 errorMessage = test.stderr
              }
              else{ // Wrong Answer, TLE, etc.
                 status = 'wrong'
                 errorMessage = test.stderr
              }
            }
        }

        // 4. Update and Save Submission Result
        submittedResult.status = status;
        submittedResult.testCasesPassed = testCasesPassed;
        submittedResult.errorMessage = errorMessage;
        submittedResult.runtime = runtime;
        submittedResult.memory = memory;

        await submittedResult.save();
        
        // 5. Update User Solved List
        if(status === 'accepted' && req.result && req.result.problemSolved && !req.result.problemSolved.includes(problemId)){
          req.result.problemSolved.push(problemId);
          await req.result.save();
        }
        
        // 6. Send Final Success Response (MUST use return)
        const accepted = (status == 'accepted');
        return res.status(201).json({
          accepted,
          totalTestCases: submittedResult.testCasesTotal,
          passedTestCases: testCasesPassed,
          runtime,
          memory
        });
        
    }
    catch(err){
      // CRITICAL FIX: Return immediately after sending 500 error
      console.error("Submission error:", err); 
      return res.status(500).send("Internal Server Error "+ err);
    }
}


const runCode = async(req,res)=>{
     try{
      const userId = req.result._id;
      const problemId = req.params.id;
 
      let {code,language} = req.body;
 
      if(!userId||!code||!problemId||!language)
        return res.status(400).send("Some field missing");
 
      const problem =  await Problem.findById(problemId);
      
      if (!problem) {
        return res.status(404).send("Problem not found");
      }
      
      if(language==='cpp')
        language='c++'
 
      const languageId = getLanguageById(language);
 
      const submissions = problem.visibleTestCases.map((testcase)=>({
        source_code:code,
        language_id: languageId,
        stdin: testcase.input,
        expected_output: testcase.output
      }));
 
      const submitResult = await submitBatch(submissions);
      const resultToken = submitResult.map((value)=> value.token);
      const testResult = await submitToken(resultToken);
 
      let runtime = 0;
      let memory = 0;
      let status = true;
 
      for(const test of testResult){
          if(test.status_id==3){
             runtime = runtime+parseFloat(test.time)
             memory = Math.max(memory,test.memory);
          }else{
            status = false
          }
      }
 
      return res.status(201).json({
        success:status,
        testCases: testResult,
        runtime,
        memory
      });
        
     }
     catch(err){
       return res.status(500).send("Internal Server Error "+ err);
     }
}

// ⭐ NEW FUNCTION: Handles the "No submission yet" logic
const getSubmissionHistory = async (req, res) => {
    try {
        const userId = req.result._id;
        const problemId = req.params.id;

        // Find all submissions for the user and problem
        const submissions = await Submission.find({ 
            userId: userId, 
            problemId: problemId 
        })
        .sort({ createdAt: -1 }) // Sort by newest first
        .select('-code'); // Exclude the code content

        // Check if the array of submissions is empty
        if (submissions.length === 0) {
            // If no submissions exist, send a 404 response with the message
            return res.status(404).json({ message: "No submission yet." });
        }

        // If submissions are found, send the data
        return res.status(200).json(submissions);

    } catch (err) {
        console.error("Error fetching submissions:", err);
        return res.status(500).send("Internal Server Error while fetching submission history.");
    }
}


module.exports = {submitCode,runCode, getSubmissionHistory};