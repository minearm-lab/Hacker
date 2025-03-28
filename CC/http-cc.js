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