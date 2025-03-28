const net = require('net');
// 最大请求次数
const MAX_REQUESTS = 100;
// 目标服务器地址和端口
const target = {
    host: 'example.com',
    port: 8080
};

// 循环发送多次 TCP 请求
for (let i = 0; i < MAX_REQUESTS; i++) {
    // 创建 TCP 套接字并连接到目标服务器
    const socket = net.createConnection(target.port, target.host, () => {
        console.log(`已连接到 ${target.host}:${target.port}`);
        const message = 'Test TCP message';
        // 向服务器发送消息
        socket.write(message);
    });

    // 监听服务器返回的数据
    socket.on('data', (data) => {
        console.log(`收到 TCP 响应: ${data.toString()}`);
        // 关闭连接
        socket.end();
    });

    // 监听连接关闭事件
    socket.on('end', () => {
        console.log('TCP 连接已关闭');
    });

    // 监听错误事件
    socket.on('error', (err) => {
        console.log(`TCP 请求出错: ${err.message}`);
    });
}