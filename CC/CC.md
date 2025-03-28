# 网络请求压力测试工具
## 项目概述
## 本项目提供了多种网络请求压力测试工具，包括 HTTP、TCP 和 UDP 请求的并发测试脚本。这些脚本可以帮助你模拟大量的网络请求，以测试服务器的性能和稳定性。
[仓库地址](https://github.com/Minearm-Lab/Hacker)
## 开源协议
本项目采用 GPL - 3.0 开源协议。
## 代码结构
1. HTTP 请求压力测试 (http-cc.js)
此脚本用于模拟并发的 HTTP 请求，支持使用 axios 或 fetch API 发送请求。
```javascript
let axios;
if (typeof module !== 'undefined' && typeof require === 'function') {
    try {
        axios = require('axios');
    } catch (err) {
        console.log('在 Node.js 环境无法引入 axios，可考虑使用 CDN 或安装依赖。');
    }
}

// 定义并发和最大请求次数
const CONCURRENCY = 10;
const MAX_REQUESTS = 100;

// 若在浏览器环境且 axios 未定义，可动态创建 script 标签引入 CDN
if (typeof window !== 'undefined' && typeof axios === 'undefined') {
    const script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js';
    script.onload = () => {
        axios = window.axios;
        runHttpRequests();
    };
    script.onerror = () => {
        console.log('无法从 CDN 加载 axios，无法使用 axios 发送请求。');
    };
    document.head.appendChild(script);
} else {
    if (typeof axios === 'undefined') {
        console.log('未找到 axios，尝试使用 fetch API。');
    }
    runHttpRequests();
}

async function sendSingleHTTPRequest(url, proxy) {
    const config = { timeout: 5000 };
    if (proxy) {
        console.warn('浏览器环境不支持 socks 代理，proxy 参数将被忽略。');
    }
    try {
        let response;
        if (axios) {
            response = await axios.get(url, config);
            console.log(`成功向 ${url} 发送 HTTP 请求，状态码: ${response.status}`);
        } else if (typeof fetch === 'function') {
            response = await fetch(url, {
                method: 'GET',
                cache: 'no-cache',
                headers: {
                    'Content-Type': 'application/json'
                },
                ...config
            });
            console.log(`成功向 ${url} 发送 HTTP 请求，状态码: ${response.status}`);
        } else {
            console.log('既无 axios 也无 fetch 可用，无法发送 HTTP 请求。');
        }
        return response;
    } catch (error) {
        console.log(`HTTP 请求出错: ${error.message}`);
        return null;
    }
}

async function sendConcurrentHTTPRequests(url, proxy) {
    const requests = Array.from({ length: CONCURRENCY }, () => sendSingleHTTPRequest(url, proxy));
    return Promise.all(requests);
}

async function runHttpRequests() {
    const url = 'http://example.com';
    const proxy = null;
    const allPromises = [];
    for (let i = 0; i < MAX_REQUESTS; i++) {
        allPromises.push(sendConcurrentHTTPRequests(url, proxy));
    }
    await Promise.all(allPromises);
}
```

2. TCP 请求压力测试 (tcp-cc.js)
此脚本用于模拟并发的 TCP 请求，通过 net 模块创建 TCP 套接字并发送请求。
```javascript
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
3. UDP 请求压力测试 (udp-cc.js)
此脚本用于模拟并发的 UDP 请求，通过 dgram 模块创建 UDP 套接字并发送请求。
javascript
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
```

# 使用方法
HTTP 请求压力测试
确保已经安装了 axios 依赖（如果在 Node.js 环境中）：
```bash
npm install axios
```
运行脚本：
```bash
node http-cc.js
```
TCP 请求压力测试
运行脚本：
```bash
node tcp-cc.js
```
UDP 请求压力测试
运行脚本：
```bash
node udp-cc.js
```
# 注意事项
# 该项目仅供参考和学习，禁止用于非法用途!

注: 可以根据需要修改脚本中的 MAX_REQUESTS、CONCURRENCY、target 等参数来调整测试的强度和目标。