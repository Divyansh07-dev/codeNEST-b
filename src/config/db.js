const mongoose = require('mongoose');
async function main(){
    // await mongoose.connect('mongodb://localhost:27017/MyDB', {
    await mongoose.connect(process.env.DB_CONNECT_STRING )
}
module.exports = main;


