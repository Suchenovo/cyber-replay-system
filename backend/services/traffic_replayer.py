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

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Redis 配置
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = 6379

class TrafficReplayer:
    """流量重放器 (TCPreplay 高性能优化版)"""

    def __init__(self, pcap_file=None):
        self.pcap_file = pcap_file
        try:
            # 初始化 Docker 客户端
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"Docker client init failed: {e}")
            self.docker_client = None
        
        try:
            # 初始化 Redis 连接
            self.redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            self.redis = None

    def _save_task(self, task_id, data):
        """保存任务状态到 Redis"""
        if self.redis:
            self.redis.set(f"replay_task:{task_id}", json.dumps(data))
    
    def _get_task(self, task_id):
        """从 Redis 获取任务状态"""
        if self.redis:
            data = self.redis.get(f"replay_task:{task_id}")
            return json.loads(data) if data else None
        return None

    def _copy_to_container(self, container, src_path, dst_path):
        """将文件复制到 Docker 容器内"""
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
        生成在容器内部运行的 Python 脚本。
        包含：pcapng自动转换、动态网卡检测、IO死锁防护。
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

def get_interface():
    # 自动查找容器内可用网卡
    try:
        interfaces = os.listdir('/sys/class/net/')
        for iface in interfaces:
            if iface != 'lo': return iface
        return 'eth0'
    except: return 'eth0'

try:
    final_pcap = pcap_path

    # ==========================================
    # 1. 【新增】自动检测并转换 pcapng -> pcap
    # ==========================================
    # tcpreplay 不支持 pcapng，既然容器里装了 tshark，我们就用它转一下
    if pcap_path.endswith('.pcapng') or 'pcapng' in pcap_path:
        print("Converting pcapng to pcap...")
        converted_pcap = pcap_path + ".converted.pcap"
        # 使用 tshark 进行转换 (-F pcap 指定输出格式)
        convert_cmd = [
            "tshark", "-F", "pcap", "-r", pcap_path, "-w", converted_pcap
        ]
        # 使用 DEVNULL 防止输出阻塞
        subprocess.run(convert_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        final_pcap = converted_pcap

    # 2. 估算包数量
    try:
        file_size = os.path.getsize(final_pcap)
        total_packets = int(file_size / 800) # 粗略估算
        if total_packets == 0: total_packets = 100
    except:
        total_packets = 1000

    update_status(0, total_packets, "running")

    # 3. IP 重写 (tcprewrite)
    if target_ip != "None":
        rewritten_pcap = final_pcap + ".rewrite.pcap"
        rewrite_cmd = [
            "tcprewrite",
            "--dstipmap=0.0.0.0/0:" + target_ip,
            "--infile=" + final_pcap,
            "--outfile=" + rewritten_pcap,
            "--checksum" 
        ]
        subprocess.run(rewrite_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        final_pcap = rewritten_pcap

    # 4. 执行重放
    interface = get_interface()
    
    replay_cmd = [
        "tcpreplay",
        "-i", interface,
        "-x", str(speed),
        "--quiet",
        final_pcap
    ]
    
    # 解决死锁的关键：stdout=subprocess.DEVNULL
    process = subprocess.Popen(replay_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    
    while process.poll() is None:
        if os.path.exists(stop_path):
            process.terminate()
            update_status(0, total_packets, "stopped")
            sys.exit(0)
        time.sleep(0.5)
    
    _, stderr = process.communicate()
    
    if process.returncode != 0:
        err_msg = stderr.decode() if stderr else "Unknown error"
        raise Exception(f"tcpreplay failed: {{err_msg}}")

    update_status(total_packets, total_packets, "completed")

except Exception as e:
    update_status(0, 0, "failed", str(e))
    sys.exit(1)
"""

    def start_replay(self, target_ip: Optional[str] = None, speed_multiplier: float = 1.0, use_sandbox: bool = True):
        """启动重放任务"""
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

        # 异步线程执行，不阻塞 API
        thread = threading.Thread(
            target=self._task_manager_thread,
            args=(task_id, target_ip, speed_multiplier, use_sandbox),
        )
        thread.daemon = True
        thread.start()
        return task_id

    def _task_manager_thread(self, task_id, target_ip, speed_multiplier, use_sandbox):
        """任务管理线程"""
        try:
            if use_sandbox:
                self._run_sandbox_replay(task_id, target_ip, speed_multiplier)
            else:
                # 暂不支持本地模式，直接标记失败
                task = self._get_task(task_id)
                task.update({"status": "failed", "error": "Local mode not supported without docker"})
                self._save_task(task_id, task)
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            task = self._get_task(task_id) or {}
            task.update({"status": "failed", "error": str(e)})
            self._save_task(task_id, task)

    def _run_sandbox_replay(self, task_id, target_ip, speed):
        """在 Docker 沙箱中执行重放"""
        if not self.docker_client: raise Exception("Docker client not available")
        
        # 获取沙箱容器
        try:
            container = self.docker_client.containers.get('cyber-replay-sandbox')
        except docker.errors.NotFound:
            raise Exception("Sandbox container (cyber-replay-sandbox) is not running")

        # 定义容器内路径
        sandbox_pcap = f"/tmp/{task_id}.pcap"
        sandbox_script = f"/tmp/replay_{task_id}.py"
        status_file = f"/tmp/{task_id}.status"
        stop_file = f"/tmp/{task_id}.stop"

        # 1. 上传 PCAP 文件
        if not self.pcap_file or not os.path.exists(self.pcap_file):
            raise Exception("PCAP file not found")
        self._copy_to_container(container, self.pcap_file, sandbox_pcap)
        
        # 2. 生成并上传 Python 执行脚本
        script_content = self._generate_replay_script(
            sandbox_pcap, status_file, stop_file, target_ip or "None", speed
        )
        
        local_script_path = f"/tmp/replay_{task_id}.py"
        # 确保本地 tmp 目录存在
        os.makedirs(os.path.dirname(local_script_path), exist_ok=True)
        
        with open(local_script_path, "w", encoding='utf-8') as f: 
            f.write(script_content)
        
        self._copy_to_container(container, local_script_path, sandbox_script)
        os.remove(local_script_path)

        # 3. 在容器内异步执行脚本
        container.exec_run(f"python3 {sandbox_script}", detach=True)
        
        # 4. 轮询监控状态文件
        task = self._get_task(task_id)
        task["status"] = "running"
        self._save_task(task_id, task)
        
        while True:
            # 检查是否需要停止
            current_task = self._get_task(task_id)
            if current_task.get("stop_requested"):
                container.exec_run(f"touch {stop_file}")
            
            # 读取容器内的状态文件
            try:
                exit_code, output = container.exec_run(f"cat {status_file}")
                if exit_code == 0 and output:
                    status_data = json.loads(output.decode('utf-8'))
                    
                    # 更新 Redis 状态
                    current_task.update({
                        "sent_packets": status_data.get("sent_packets", 0),
                        "total_packets": status_data.get("total_packets", 100)
                    })
                    
                    # 计算进度条
                    status_str = status_data.get("status")
                    if status_str == "completed":
                        current_task["progress"] = 100
                    elif status_str == "running":
                        # 因为无法实时获取精确进度，如果是运行中，我们就显示 50% 或做一个假动画
                        # 或者你可以根据 time.time() - start_time 做一个估算
                        current_task["progress"] = 50 
                    
                    if status_str in ["completed", "stopped", "failed"]:
                        current_task["status"] = status_str
                        if status_str == "failed":
                            current_task["error"] = status_data.get("error")
                        self._save_task(task_id, current_task)
                        break # 结束循环
                    
                    self._save_task(task_id, current_task)
            except Exception:
                # 忽略读取过程中的瞬时错误（如文件正被写入）
                pass

            time.sleep(0.5) # 轮询间隔
        
        # 5. 清理容器内临时文件
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