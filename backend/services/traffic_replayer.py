import docker
import time
import json
import threading
import os
import tarfile
import io
import uuid
import logging
import redis
from scapy.all import PcapReader
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = 6379

class TrafficReplayer:
    """流量重放器 (TCPreplay 高性能版)"""

    def __init__(self, pcap_file=None):
        self.pcap_file = pcap_file
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"Docker client init failed: {e}")
            self.docker_client = None
        
        try:
            self.redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            self.redis = None

    def _save_task(self, task_id, data):
        if self.redis:
            self.redis.set(f"replay_task:{task_id}", json.dumps(data))
    
    def _get_task(self, task_id):
        if self.redis:
            data = self.redis.get(f"replay_task:{task_id}")
            return json.loads(data) if data else None
        return None

    def _copy_to_container(self, container, src_path, dst_path):
        try:
            with open(src_path, 'rb') as f:
                file_data = f.read()
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                tar_info = tarfile.TarInfo(name=os.path.basename(dst_path))
                tar_info.size = len(file_data)
                tar.addfile(tar_info, io.BytesIO(file_data))
            tar_stream.seek(0)
            container.put_archive(path=os.path.dirname(dst_path), data=tar_stream)
        except Exception as e:
            logger.error(f"Failed to copy file to container: {e}")
            raise

    def _generate_replay_script(self, pcap_path, status_path, stop_path, target_ip, speed):
        """
        生成调用系统级工具 tcpreplay 的脚本
        """
        return f"""
import sys
import time
import json
import os
import subprocess
from scapy.all import PcapReader

pcap_path = "{pcap_path}"
status_path = "{status_path}"
stop_path = "{stop_path}"
target_ip = "{target_ip}"
speed = {speed}

def update_status(sent, total, status="running", error=None):
    data = {{
        "sent_packets": sent,
        "total_packets": total,
        "status": status,
        "error": error,
        "timestamp": time.time()
    }}
    tmp_path = status_path + ".tmp"
    with open(tmp_path, "w") as f: json.dump(data, f)
    os.rename(tmp_path, status_path)

try:
    # 1. 简单统计总包数 (用于前端显示总量)
    total_packets = 0
    # 为了极速，这里也可以跳过，直接设为 100 或根据文件大小估算
    # 但为了体验好，还是读一下头
    try:
        for _ in PcapReader(pcap_path): total_packets += 1
    except: pass
    
    update_status(0, total_packets, "running")

    # 2. 准备命令
    final_pcap = pcap_path
    
    # 如果需要修改 IP，使用 tcprewrite (比 Python 快得多)
    if target_ip != "None":
        rewritten_pcap = pcap_path + ".rewrite.pcap"
        # --dstipmap=0.0.0.0/0:TARGET_IP 将所有目标IP重写为 target_ip
        # -C 修复校验和
        rewrite_cmd = [
            "tcprewrite",
            "--dstipmap=0.0.0.0/0:" + target_ip,
            "--infile=" + pcap_path,
            "--outfile=" + rewritten_pcap,
            "--checksum" 
        ]
        print(f"Executing: {{' '.join(rewrite_cmd)}}")
        subprocess.run(rewrite_cmd, check=True)
        final_pcap = rewritten_pcap

    # 3. 使用 tcpreplay 发送
    # -i eth0: 指定网卡
    # -x speed: 倍速播放
    # --quiet: 减少输出
    replay_cmd = [
        "tcpreplay",
        "-i", "eth0",
        "-x", str(speed),
        final_pcap
    ]
    
    print(f"Executing: {{' '.join(replay_cmd)}}")
    
    # 使用 Popen 运行，这样我们可以非阻塞地等待它完成
    # 注意：tcpreplay 运行极快，可能瞬间就结束了，很难抓取实时进度
    # 所以我们直接在开始时设为 running，结束时设为 completed
    process = subprocess.Popen(replay_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # 简单的监控循环
    while process.poll() is None:
        if os.path.exists(stop_path):
            process.terminate()
            update_status(0, total_packets, "stopped")
            sys.exit(0)
        time.sleep(0.5)
    
    stdout, stderr = process.communicate()
    
    if process.returncode != 0:
        raise Exception(f"tcpreplay failed: {{stderr.decode()}}")

    update_status(total_packets, total_packets, "completed")

except Exception as e:
    update_status(0, 0, "failed", str(e))
    sys.exit(1)
"""

    def start_replay(self, target_ip: Optional[str] = None, speed_multiplier: float = 1.0, use_sandbox: bool = True):
        task_id = str(uuid.uuid4())
        initial_state = {
            "task_id": task_id,
            "status": "initializing",
            "progress": 0,
            "total_packets": 0,
            "sent_packets": 0,
            "start_time": time.time(),
            "mode": "sandbox" if use_sandbox else "local"
        }
        self._save_task(task_id, initial_state)

        thread = threading.Thread(
            target=self._task_manager_thread,
            args=(task_id, target_ip, speed_multiplier, use_sandbox),
        )
        thread.daemon = True
        thread.start()
        return task_id

    def _task_manager_thread(self, task_id, target_ip, speed_multiplier, use_sandbox):
        try:
            if use_sandbox:
                self._run_sandbox_replay(task_id, target_ip, speed_multiplier)
            else:
                # 本地模式我们暂时不支持 tcpreplay (因为它依赖宿主机环境)，
                # 如果你在 Docker 里跑 backend，这里其实也可以改，
                # 但为了简单，本地模式先留空或报错，或者保留旧的 Scapy 逻辑
                pass 
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            task = self._get_task(task_id) or {}
            task.update({"status": "failed", "error": str(e)})
            self._save_task(task_id, task)

    def _run_sandbox_replay(self, task_id, target_ip, speed):
        if not self.docker_client: raise Exception("Docker client not available")
        container = self.docker_client.containers.get('cyber-replay-sandbox')
        
        sandbox_pcap = f"/tmp/{task_id}.pcap"
        sandbox_script = f"/tmp/replay_{task_id}.py"
        status_file = f"/tmp/{task_id}.status"
        stop_file = f"/tmp/{task_id}.stop"

        self._copy_to_container(container, self.pcap_file, sandbox_pcap)
        
        # 生成脚本
        script_content = self._generate_replay_script(
            sandbox_pcap, status_file, stop_file, target_ip or "None", speed
        )
        
        local_script_path = f"/tmp/replay_{task_id}.py"
        with open(local_script_path, "w") as f: f.write(script_content)
        self._copy_to_container(container, local_script_path, sandbox_script)
        os.remove(local_script_path)

        # 启动
        container.exec_run(f"python3 {sandbox_script}", detach=True)
        
        # 监控循环
        task = self._get_task(task_id)
        task["status"] = "running"
        self._save_task(task_id, task)
        
        while True:
            # 处理停止信号
            current_task = self._get_task(task_id)
            if current_task.get("stop_requested"):
                container.exec_run(f"touch {stop_file}")
            
            # 读取状态
            try:
                exit_code, output = container.exec_run(f"cat {status_file}")
                if exit_code == 0 and output:
                    status_data = json.loads(output.decode('utf-8'))
                    
                    # 更新进度
                    current_task.update({
                        "sent_packets": status_data["sent_packets"],
                        "total_packets": status_data["total_packets"]
                    })
                    
                    if status_data["total_packets"] > 0:
                        # 简单的进度计算：如果完成了就是 100，否则就是 0 或 50 (tcpreplay 很难拿实时百分比)
                        if status_data["status"] == "completed":
                            current_task["progress"] = 100
                        elif status_data["status"] == "running":
                            current_task["progress"] = 50 # 假进度，表示正在跑
                    
                    script_status = status_data.get("status")
                    if script_status in ["completed", "stopped", "failed"]:
                        current_task["status"] = script_status
                        if script_status == "failed":
                            current_task["error"] = status_data.get("error")
                        self._save_task(task_id, current_task)
                        break
                    
                    self._save_task(task_id, current_task)
            except Exception:
                pass

            time.sleep(0.5) # 提高轮询频率
        
        # 清理
        container.exec_run(f"rm {sandbox_pcap} {sandbox_script} {status_file} {stop_file}")

    def get_status(self, task_id: str):
        task = self._get_task(task_id)
        if not task: raise Exception("任务不存在")
        return task

    def stop_replay(self, task_id: str):
        task = self._get_task(task_id)
        if task:
            task["stop_requested"] = True
            self._save_task(task_id, task)
            return {"message": "Stopping task...", "task_id": task_id}
        raise Exception("Task not found")

    def list_tasks(self):
        if not self.redis: return []
        keys = self.redis.keys("replay_task:*")
        tasks = []
        for k in keys:
            data = self.redis.get(k)
            if data: tasks.append(json.loads(data))
        return tasks