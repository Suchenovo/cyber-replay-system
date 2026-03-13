import docker
import time
import json
import threading
import os
import tarfile
import uuid
import logging
import redis
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = 6379


class TrafficReplayer:
    """下一代流量重放器 (Docker Stream 流式通信防死锁版)"""

    def __init__(self, pcap_file: str = None):
        self.pcap_file = pcap_file
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"Docker client init failed: {e}")
            self.docker_client = None

        try:
            self.redis = redis.Redis(
                host=REDIS_HOST, port=REDIS_PORT, decode_responses=True
            )
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            self.redis = None

    def _save_task(self, task_id: str, data: dict):
        if self.redis:
            self.redis.set(f"replay_task:{task_id}", json.dumps(data))

    def _get_task(self, task_id: str) -> dict:
        if self.redis:
            data = self.redis.get(f"replay_task:{task_id}")
            return json.loads(data) if data else None
        return None

    def _copy_to_container_safe(self, container, src_path: str, dst_path: str):
        """修复 OOM 隐患：使用临时文件打包，避免大文件直接塞入内存"""
        tar_path = f"{src_path}.tar"
        try:
            # 1. 将文件打包到本地磁盘临时 tar 文件中 (极其省内存)
            with tarfile.open(tar_path, mode="w") as tar:
                tar.add(src_path, arcname=os.path.basename(dst_path))

            # 2. 以二进制流读取发给 Docker
            with open(tar_path, "rb") as f:
                logger.info(f"Uploading {src_path} -> {container.name}:{dst_path}")
                container.put_archive(path=os.path.dirname(dst_path), data=f)
        except Exception as e:
            logger.error(f"Failed to copy file to container: {e}")
            raise
        finally:
            if os.path.exists(tar_path):
                os.remove(tar_path)

    def _generate_sandbox_script(
        self, pcap_path: str, target_ip: str, speed: float
    ) -> str:
        """
        沙箱内部执行脚本。
        核心改变：直接将进度通过 JSON 格式 print 到 stdout。宿主机通过 docker stream 实时捕获。
        """
        return f"""
import sys
import time
import json
import os
import subprocess

pcap_path = "{pcap_path}"
target_ip = "{target_ip}"
speed = {speed}

def emit_status(sent, total, status, msg=""):
    # 将状态直接打印到标准输出，外层可以实时截获
    out = json.dumps({{
        "sent": sent, "total": total, "status": status, 
        "msg": msg, "ts": time.time()
    }})
    print(f"[[STATUS_SYNC]]|{{out}}", flush=True)

try:
    emit_status(0, 100, "preparing", "Starting environment setup...")
    
    # 获取包数
    file_size = os.path.getsize(pcap_path)
    total_packets = max(100, int(file_size / 800))  # 粗略估算，后续可由 tcpreplay 输出修正
    
    emit_status(0, total_packets, "running", "Applying IP/MAC rewrite rules...")
    
    # 查找网卡 (排除 lo 本地环回)
    iface = 'eth0'
    for name in os.listdir('/sys/class/net'):
        if name != 'lo':
            iface = name
            break

    # 组装 tcpreplay 命令
    cmd = ["tcpreplay", "-i", iface]
    if speed >= 999: # 约等于极限速度
        cmd.append("--topspeed")
    else:
        cmd.extend(["-x", str(speed)])
    
    cmd.append(pcap_path)

    emit_status(0, total_packets, "running", f"Starting packet injection on {{iface}}...")
    
    # 启动发包 (带实时输出)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    
    sent_pkts = 0
    for line in iter(process.stdout.readline, ""):
        line = line.strip()
        if line:
            # 你可以将 tcpreplay 的实时日志通过 MSG 字段传出去
            emit_status(sent_pkts, total_packets, "running", line)
            
    process.stdout.close()
    process.wait()

    if process.returncode != 0:
        raise Exception(f"tcpreplay exit code {{process.returncode}}")

    emit_status(total_packets, total_packets, "completed", "Replay finished successfully.")

except Exception as e:
    emit_status(0, 0, "failed", f"ERROR: {{str(e)}}")
    sys.exit(1)
"""

    def start_replay(
        self,
        target_ip: Optional[str] = None,
        speed_multiplier: float = 1.0,
        use_sandbox: bool = True,
    ):
        if not self.pcap_file or not os.path.exists(self.pcap_file):
            raise FileNotFoundError("PCAP file is missing")

        task_id = str(uuid.uuid4())
        initial_state = {
            "task_id": task_id,
            "status": "initializing",
            "progress": 0,
            "sent_packets": 0,
            "total_packets": 0,
            "logs": [],  # 新增：用于存储前端展示的终端日志
            "start_time": time.time(),
        }
        self._save_task(task_id, initial_state)

        thread = threading.Thread(
            target=self._run_sandbox_stream_replay,
            args=(task_id, target_ip, speed_multiplier),
        )
        thread.daemon = True
        thread.start()
        return task_id

    def _run_sandbox_stream_replay(self, task_id: str, target_ip: str, speed: float):
        task = self._get_task(task_id) or {}
        try:
            container = self.docker_client.containers.get("cyber-replay-sandbox")

            sandbox_pcap = f"/tmp/{task_id}.pcap"
            sandbox_script = f"/tmp/replay_{task_id}.py"

            # 1. 复制文件
            self._copy_to_container_safe(container, self.pcap_file, sandbox_pcap)

            # 2. 生成并复制脚本
            script_content = self._generate_sandbox_script(
                sandbox_pcap, target_ip or "None", speed
            )
            local_script = f"/tmp/script_{task_id}.py"
            with open(local_script, "w") as f:
                f.write(script_content)
            self._copy_to_container_safe(container, local_script, sandbox_script)
            os.remove(local_script)

            task.update({"status": "starting", "progress": 5})
            self._save_task(task_id, task)

            # 3. 执行脚本并流式捕获输出 (关键改进：不会死锁)
            # 注意: exec_run 返回一个生成器，我们可以一行行读取容器输出
            exec_obj = container.exec_run(
                f"python3 {sandbox_script}", stream=True, detach=False
            )

            for output_bytes in exec_obj.output:
                output_str = output_bytes.decode("utf-8", errors="ignore").strip()
                if not output_str:
                    continue

                # 解析从沙箱脚本打印出的状态
                if "[[STATUS_SYNC]]|" in output_str:
                    try:
                        json_str = output_str.split("[[STATUS_SYNC]]|")[1]
                        sync_data = json.loads(json_str)

                        sent = sync_data.get("sent", 0)
                        total = sync_data.get("total", 100)
                        status = sync_data.get("status", "running")
                        msg = sync_data.get("msg", "")

                        # 保存日志到列表，供前端拉取
                        if msg:
                            # 限制日志长度防止爆内存
                            task.setdefault("logs", []).append(
                                f"[{time.strftime('%H:%M:%S')}] {msg}"
                            )
                            task["logs"] = task["logs"][-50:]

                        task.update(
                            {
                                "status": status,
                                "sent_packets": sent,
                                "total_packets": total,
                                "progress": (
                                    int((sent / total) * 100) if total > 0 else 0
                                ),
                                "end_time": (
                                    time.time()
                                    if status in ["completed", "failed"]
                                    else None
                                ),
                            }
                        )
                        self._save_task(task_id, task)
                    except Exception as e:
                        logger.warning(f"Failed to parse sync data: {e}")

        except docker.errors.NotFound:
            task.update(
                {
                    "status": "failed",
                    "error": "Sandbox container 'cyber-replay-sandbox' is not running.",
                }
            )
            self._save_task(task_id, task)
        except Exception as e:
            logger.error(f"Replay task failed: {e}")
            task.update({"status": "failed", "error": str(e)})
            self._save_task(task_id, task)

    def get_status(self, task_id: str):
        return self._get_task(task_id)

    def list_tasks(self) -> list:
        """列出 Redis 中所有的重放任务"""
        if not self.redis:
            return []
        keys = self.redis.keys("replay_task:*")
        tasks = []
        for k in keys:
            data = self.redis.get(k)
            if data:
                tasks.append(json.loads(data))
        # 按开始时间倒序排列
        tasks.sort(key=lambda x: x.get("start_time", 0), reverse=True)
        return tasks

    def stop_replay(self, task_id: str) -> dict:
        """停止重放任务"""
        task = self._get_task(task_id)
        if task:
            task["status"] = "stopping"
            self._save_task(task_id, task)
            # 实际向容器发出停止信号 (直接 kill 掉 tcpreplay 进程)
            try:
                if self.docker_client:
                    container = self.docker_client.containers.get(
                        "cyber-replay-sandbox"
                    )
                    container.exec_run("pkill tcpreplay")
            except Exception as e:
                logger.warning(f"Failed to kill tcpreplay in container: {e}")
            return {"message": "任务正在停止..."}
        return {"error": "未找到该任务"}

    def delete_task(self, task_id: str) -> dict:
        """删除重放任务及记录"""
        task = self._get_task(task_id)
        if not task:
            return {"error": "未找到该任务"}

        # 若在运行，先尝试停止
        if task.get("status") in ["initializing", "starting", "running", "stopping"]:
            try:
                self.stop_replay(task_id)
            except Exception:
                pass

        # 从 Redis 清除数据
        if self.redis:
            self.redis.delete(f"replay_task:{task_id}")
        return {"message": "任务已删除", "task_id": task_id}
