# 文件路径: backend/services/traffic_replayer.py
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
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = 6379

class TrafficReplayer:
    """流量重放器 (抗死锁稳定版)"""

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
        """修复版文件上传：增加元数据防止Docker丢包"""
        try:
            if not os.path.exists(src_path):
                raise FileNotFoundError(f"Source file not found: {src_path}")

            with open(src_path, 'rb') as f:
                file_data = f.read()
            
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                tar_info = tarfile.TarInfo(name=os.path.basename(dst_path))
                tar_info.size = len(file_data)
                tar_info.mtime = time.time()
                tar_info.mode = 0o755
                tar.addfile(tar_info, io.BytesIO(file_data))
            
            tar_stream.seek(0)
            logger.info(f"Copying {src_path} -> {container.name}:{dst_path}")
            container.put_archive(path=os.path.dirname(dst_path), data=tar_stream)
        except Exception as e:
            logger.error(f"Failed to copy file to container: {e}")
            raise

    def _generate_replay_script(self, pcap_path, status_path, stop_path, target_ip, speed):
        """
        【关键修复】
        1. 启动即写入 preparing 状态，避免长时间 0%。
        2. tshark/tcprewrite 增加超时和错误捕获，防止卡死。
        3. 更稳妥的网卡选择。
        """
        return f"""
import sys
import time
import json
import os
import subprocess

pcap_path = "{pcap_path}"
status_path = "{status_path}"
stop_path = "{stop_path}"
target_ip = "{target_ip}"
speed = {speed}
log_path = pcap_path + ".log"

def update_status(sent, total, status="running", error=None):
    data = {{
        "sent_packets": sent,
        "total_packets": total,
        "status": status,
        "error": error,
        "timestamp": time.time()
    }}
    tmp_path = status_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, status_path)

try:
    log_file = open(log_path, "w", buffering=1)

    # 提前告知前端：正在准备
    try:
        update_status(0, 100, "preparing", None)
    except Exception:
        pass

    final_pcap = pcap_path

    # 1. 如是 pcapng，进行转换（带超时）
    if pcap_path.endswith('.pcapng') or 'pcapng' in pcap_path:
        log_file.write("Converting pcapng...\\n")
        converted_pcap = pcap_path + ".converted.pcap"
        try:
            subprocess.run(
                ["tshark", "-F", "pcap", "-r", pcap_path, "-w", converted_pcap],
                stdout=log_file, stderr=subprocess.STDOUT, check=True, timeout=120
            )
            final_pcap = converted_pcap
        except subprocess.TimeoutExpired:
            update_status(0, 0, "failed", "tshark convert timeout")
            sys.exit(1)
        except Exception as e:
            update_status(0, 0, "failed", f"tshark error: {{e}}")
            sys.exit(1)

    # 2. 估算包数和时长（保证 speed 有效）
    file_size = os.path.getsize(final_pcap)
    total_packets = max(100, int(file_size / 800))
    if not isinstance(speed, (int, float)) or speed <= 0:
        speed = 1.0
    estimated_duration = (file_size / (1024*1024)) / speed
    start_time = time.time()

    update_status(0, total_packets, "running")

    # 3. IP 重写（带超时）
    if target_ip != "None":
        log_file.write(f"Rewriting IP to {{target_ip}}...\\n")
        rewritten_pcap = final_pcap + ".rewrite.pcap"
        try:
            subprocess.run(
                ["tcprewrite", "--dstipmap=0.0.0.0/0:" + target_ip,
                 "--infile=" + final_pcap, "--outfile=" + rewritten_pcap, "--checksum"],
                stdout=log_file, stderr=subprocess.STDOUT, check=True, timeout=120
            )
            final_pcap = rewritten_pcap
        except subprocess.TimeoutExpired:
            update_status(0, 0, "failed", "tcprewrite timeout")
            sys.exit(1)
        except Exception as e:
            update_status(0, 0, "failed", f"tcprewrite error: {{e}}")
            sys.exit(1)

    # 4. 选择网卡
    iface = 'eth0'
    try:
        for name in os.listdir('/sys/class/net'):
            if name != 'lo':
                iface = name
                break
    except Exception:
        pass

    log_file.write(f"Starting replay on {{iface}}...\\n")
    log_file.flush()

    # 启动 tcpreplay
    if use_topspeed:
        tcpreplay_cmd = ["tcpreplay", "--topspeed", "-i", iface, "--verbose", final_pcap]
    else:
        tcpreplay_cmd = ["tcpreplay", "-x", str(speed), "-i", iface, "--verbose", final_pcap]

    process = subprocess.Popen(
        tcpreplay_cmd,
        stdout=log_file, stderr=subprocess.STDOUT
    )

    # 循环监控 + 时间估算进度
    while process.poll() is None:
        # 停止信号
        if os.path.exists(stop_path):
            try:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
            finally:
                update_status(0, total_packets, "stopped")
                sys.exit(0)

        elapsed = time.time() - start_time
        fake_progress = int((elapsed / (estimated_duration + 5.0)) * total_packets)
        current_packets = min(fake_progress, int(total_packets * 0.99))
        update_status(current_packets, total_packets, "running")
        time.sleep(0.5)

    log_file.close()

    if process.returncode != 0:
        err_msg = "Check logs"
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
                if lines:
                    err_msg = lines[-1].strip()
        except Exception:
            pass
        raise Exception(f"tcpreplay failed: {{err_msg}}")

    update_status(total_packets, total_packets, "completed")

except Exception as e:
    try:
        with open(log_path, "a") as f:
            f.write(f"\\nCRITICAL: {{str(e)}}\\n")
    except Exception:
        pass
    try:
        update_status(0, 0, "failed", str(e))
    except Exception:
        pass
    sys.exit(1)
"""

    def start_replay(self, target_ip: Optional[str] = None, speed_multiplier: float = 1.0, use_sandbox: bool = True):
        task_id = str(uuid.uuid4())
        initial_state = {
            "task_id": task_id,
            "status": "initializing",
            "progress": 0,
            "mode": "sandbox",
            "sent_packets": 0,
            "total_packets": 0,
            "start_time": None,
            "end_time": None,
            "pcap_file": os.path.basename(self.pcap_file) if self.pcap_file else None
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
            self._run_sandbox_replay(task_id, target_ip, speed_multiplier)
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            task = self._get_task(task_id) or {}
            task.update({"status": "failed", "error": str(e)})
            self._save_task(task_id, task)

    def _run_sandbox_replay(self, task_id, target_ip, speed):
        # 1. 检查容器
        try:
            container = self.docker_client.containers.get('cyber-replay-sandbox')
        except docker.errors.NotFound:
            raise Exception("Sandbox container not found")

        # 2. 准备路径
        sandbox_pcap = f"/tmp/{task_id}.pcap"
        sandbox_script = f"/tmp/replay_{task_id}.py"
        status_file = f"/tmp/{task_id}.status"
        
        # 3. 上传文件
        self._copy_to_container(container, self.pcap_file, sandbox_pcap)
        
        script_content = self._generate_replay_script(
            sandbox_pcap, status_file, f"/tmp/{task_id}.stop", target_ip or "None", speed
        )
        
        local_script = f"/tmp/replay_{task_id}.py"
        with open(local_script, "w", encoding='utf-8') as f: f.write(script_content)
        self._copy_to_container(container, local_script, sandbox_script)
        os.remove(local_script)

        # 4. 执行 (增加超时熔断)
        container.exec_run(f"python3 {sandbox_script}", detach=True)

        # 4.1 立即设置任务为 starting，避免前端长期 initializing
        task = self._get_task(task_id) or {}
        task.update({"status": "starting", "progress": 1})
        self._save_task(task_id, task)
        
        start_wait = time.time()
        while True:
            # 超时保护 (20秒没动静就报错)
            if time.time() - start_wait > 20:
                raise Exception("Sandbox script timeout. Possible pcap format error or container lock.")

            try:
                exit_code, output = container.exec_run(f"cat {status_file}")
                if exit_code == 0:
                    # 只要能读到文件就重置计时器，哪怕解析失败
                    start_wait = time.time()

                    if output:
                        try:
                            if isinstance(output, bytes):
                                output = output.decode('utf-8', errors='ignore')
                            status_data = json.loads(output)
                        except Exception:
                            # 读取到但暂不可解析，稍后重试
                            time.sleep(0.3)
                            continue

                        task = self._get_task(task_id) or {}
                        total = status_data.get("total_packets", 100)
                        sent = status_data.get("sent_packets", 0)
                        progress = int((sent / total) * 100) if total > 0 else 0

                        # [关键修复] 补齐数据包与时间字段
                        if not task.get("start_time") and status_data.get("timestamp"):
                            task["start_time"] = status_data.get("timestamp")
                        if status_data.get("status") in ["completed", "failed", "stopped"] and status_data.get("timestamp"):
                            task["end_time"] = status_data.get("timestamp")

                        task.update({
                            "status": status_data.get("status"),
                            "progress": progress,
                            "error": status_data.get("error"),
                            "sent_packets": sent,
                            "total_packets": total
                        })
                        self._save_task(task_id, task)

                        if status_data.get("status") in ["completed", "failed", "stopped"]:
                            break
            except Exception:
                # 读取异常，稍后重试
                pass
            time.sleep(0.5)

    def get_status(self, task_id: str):
        return self._get_task(task_id)

    def list_tasks(self):
        if not self.redis: return []
        keys = self.redis.keys("replay_task:*")
        return [json.loads(self.redis.get(k)) for k in keys]

    def stop_replay(self, task_id: str):
        task = self._get_task(task_id)
        if task:
            task["stop_requested"] = True
            task["status"] = "stopping"
            self._save_task(task_id, task)
            # 实际向容器发出停止信号
            try:
                if self.docker_client:
                    container = self.docker_client.containers.get('cyber-replay-sandbox')
                    container.exec_run(f"touch /tmp/{task_id}.stop")
            except Exception as e:
                logger.warning(f"Failed to send stop signal to container: {e}")
            return {"message": "Stopping..."}
        return {"error": "Task not found"}

    def delete_task(self, task_id: str):
        task = self._get_task(task_id)
        if not task:
            return {"error": "Task not found"}

        # 若在运行，先尝试停止
        if task.get("status") in ["initializing", "starting", "preparing", "running", "stopping"]:
            try:
                self.stop_replay(task_id)
            except Exception:
                pass

        if self.redis:
            self.redis.delete(f"replay_task:{task_id}")
        return {"message": "Task deleted", "task_id": task_id}