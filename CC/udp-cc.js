const dgram = require('dgram');
// 最大请求次数
const MAX_REQUESTS = 100;
// 目标服务器地址和端口
const target = {
    host: 'example.com',
    port: 12345
};

// 创建 UDP 套接字
const client = dgram.createSocket('udp4');

// 循环发送多次 UDP 请求
for (let i = 0; i < MAX_REQUESTS; i++) {
    const message = Buffer.from('Test UDP message');
    // 向服务器发送消息
    client.send(message, 0, message.length, target.port, target.host, (err) => {
        if (err) {
            console.log(`发送 UDP 请求出错: ${err.message}`);
        } else {
            console.log(`成功向 ${target.host}:${target.port} 发送 UDP 请求`);
        }
    });
}

// 监听服务器返回的数据
client.on('message', (msg, rinfo) => {
    console.log(`收到 UDP 响应: ${msg.toString()} 来自 ${rinfo.address}:${rinfo.port}`);
});

// 监听错误事件
client.on('error', (err) => {
    console.log(`UDP 套接字出错: ${err.message}`);
    client.close();
});