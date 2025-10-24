const  { createClient } = require('redis');

const redisclient = createClient({
    username: 'default',
    password: process.env.REDIS_PASS,
   socket: {
        host: 'redis-15038.crce179.ap-south-1-1.ec2.redns.redis-cloud.com',
        port: 15038
    }
});

module.exports = redisclient;





