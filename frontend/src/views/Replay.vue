<template>
  <div class="replay-page">
    <el-card>
      <h2>流量重放</h2>
      <el-form :model="replayForm" label-width="120px">
        <el-form-item label="选择PCAP文件">
          <el-select v-model="replayForm.fileId" placeholder="请选择文件">
            <el-option
              v-for="file in pcapFiles"
              :key="file.file_id"
              :label="file.file_name || file.file_id"
              :value="file.file_id"
            />
          </el-select>
        </el-form-item>

        <el-form-item label="目标IP">
          <el-input v-model="replayForm.targetIp" placeholder="留空使用原始目标IP" />
        </el-form-item>

        <el-form-item label="重放速度">
          <el-slider v-model="replayForm.speedMultiplier" :min="0.1" :max="10" :step="0.1" />
          <span style="margin-left: 10px; color: #909399;">
            {{ replayForm.speedMultiplier }}x 倍速
          </span>
        </el-form-item>

        <el-form-item label="使用沙箱">
          <el-switch v-model="replayForm.useSandbox" />
        </el-form-item>

        <el-button type="primary" @click="startReplay" :loading="starting">
          启动重放
        </el-button>
      </el-form>
    </el-card>

    <el-card class="tasks-card">
      <template #header>
        <div class="card-header">
          <h3>重放任务</h3>
          <el-button type="primary" :icon="Refresh" @click="refreshTasks">刷新</el-button>
        </div>
      </template>

      <el-table :data="tasks" stripe>
        <el-table-column prop="task_id" label="任务ID" width="280" />
        <el-table-column label="状态" width="120">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)">
              {{ getStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="进度" width="200">
          <template #default="{ row }">
            <el-progress
              :percentage="row.progress || 0"
              :status="row.status === 'failed' ? 'exception' : row.status === 'completed' ? 'success' : undefined"
            />
          </template>
        </el-table-column>
        <el-table-column label="数据包">
          <template #default="{ row }">
            {{ row.sent_packets }} / {{ row.total_packets }}
          </template>
        </el-table-column>
        <el-table-column label="开始时间" width="180">
          <template #default="{ row }">
            {{ formatTime(row.start_time) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="260">
          <template #default="{ row }">
            <el-button size="small" type="info" @click="viewTaskDetail(row)">详情/日志</el-button>
            <el-button
              size="small"
              type="danger"
              @click="stopTask(row.task_id)"
              :disabled="!canStop(row.status)"
            >
              停止
            </el-button>
            <el-button size="small" type="warning" @click="deleteTask(row.task_id)">
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="detailDialogVisible" title="任务详情与实时监控" width="70%">
      <el-descriptions :column="2" border v-if="currentTask">
        <el-descriptions-item label="任务ID">
          {{ currentTask.task_id }}
        </el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="getStatusType(currentTask.status)">
            {{ getStatusText(currentTask.status) }}
          </el-tag>
          <span style="margin-left: 10px">{{ currentTask.progress }}%</span>
        </el-descriptions-item>
        
        <el-descriptions-item label="发包进度" :span="2">
          <el-progress 
            :percentage="currentTask.progress || 0" 
            :text-inside="true" 
            :stroke-width="20"
            :status="currentTask.status === 'failed' ? 'exception' : currentTask.status === 'completed' ? 'success' : ''"
          />
          <div style="margin-top: 5px; font-size: 12px; color: #666;">
            已发送: {{ currentTask.sent_packets }} / {{ currentTask.total_packets }}
          </div>
        </el-descriptions-item>

        <el-descriptions-item label="终端日志" :span="2">
          <div class="terminal-container" ref="terminalRef">
            <div v-if="!currentTask.logs || currentTask.logs.length === 0" class="terminal-empty">
              [SYSTEM] 正在连接沙箱，等待数据流输出...
            </div>
            <div v-for="(log, index) in currentTask.logs" :key="index" class="terminal-line">
              <span class="prompt">root@sandbox:~#</span> {{ log }}
            </div>
          </div>
        </el-descriptions-item>

        <el-descriptions-item label="错误信息" :span="2" v-if="currentTask.error">
          <el-text type="danger">{{ currentTask.error }}</el-text>
        </el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import api from '../api'

const pcapFiles = ref([])
const tasks = ref([])
const starting = ref(false)
const detailDialogVisible = ref(false)
const currentTask = ref(null)
const terminalRef = ref(null) // 用于控制终端滚动条

const replayForm = ref({
  fileId: '',
  targetIp: '',
  speedMultiplier: 1.0,
  useSandbox: true
})

let refreshTimer = null

const loadFileList = async () => {
  try {
    const result = await api.listPcaps()
    const files = result.files || result || []
    pcapFiles.value = files.map((f) => {
      if (typeof f === 'string') {
        return { file_id: f, file_name: f }
      }
      const file_id = f.file_id || f.id || f.fileId
      const file_name = f.file_name || f.filename || f.original_name || f.name || file_id
      return { ...f, file_id, file_name }
    })
  } catch (error) {
    ElMessage.error('加载文件列表失败')
  }
}

// 滚动到终端底部
const scrollToBottom = async () => {
  await nextTick()
  if (terminalRef.value) {
    terminalRef.value.scrollTop = terminalRef.value.scrollHeight
  }
}

const loadTasks = async () => {
  try {
    const result = await api.listReplayTasks()
    tasks.value = result.tasks || []

    // 【架构级优化】如果弹窗打开着，实时同步最新状态和日志
    if (detailDialogVisible.value && currentTask.value) {
      const updatedTask = tasks.value.find(t => t.task_id === currentTask.value.task_id)
      if (updatedTask) {
        currentTask.value = updatedTask
        scrollToBottom() // 每次刷新数据后，日志自动滚到底部
      }
    }
  } catch (error) {
    console.error('加载任务列表失败:', error)
  }
}

const refreshTasks = () => loadTasks()

const startReplay = async () => {
  if (!replayForm.value.fileId) {
    ElMessage.warning('请选择PCAP文件')
    return
  }
  starting.value = true
  try {
    const res = await api.startReplay(
      replayForm.value.fileId,
      replayForm.value.targetIp || null,
      replayForm.value.speedMultiplier,
      replayForm.value.useSandbox
    )
    ElMessage.success('重放任务已启动')
    await loadTasks()
    
    // 自动打开刚刚启动的任务的详情日志界面
    if (res && res.task_id) {
      const newTask = tasks.value.find(t => t.task_id === res.task_id) || { task_id: res.task_id, status: 'initializing' }
      viewTaskDetail(newTask)
    }

  } catch (error) {
    ElMessage.error('启动失败: ' + (error.response?.data?.detail || error.message))
  } finally {
    starting.value = false
  }
}

const stopTask = async (taskId) => {
  try {
    await api.stopReplay(taskId)
    ElMessage.success('任务已停止')
    await loadTasks()
  } catch (error) {
    ElMessage.error('停止失败')
  }
}

const deleteTask = async (taskId) => {
  try {
    await ElMessageBox.confirm('确定要删除该任务吗？', '警告', { type: 'warning' })
    await api.deleteReplayTask(taskId)
    ElMessage.success('任务已删除')
    detailDialogVisible.value = false // 如果正在看被删任务的详情，关掉它
    await loadTasks()
  } catch (error) {
    if (error !== 'cancel') ElMessage.error('删除失败')
  }
}

const viewTaskDetail = (task) => {
  currentTask.value = task
  detailDialogVisible.value = true
  scrollToBottom()
}

const canStop = (status) => {
  return ['initializing', 'starting', 'preparing', 'running', 'stopping'].includes(status)
}

const getStatusType = (status) => {
  const types = {
    running: 'primary',
    completed: 'success',
    failed: 'danger',
    stopped: 'warning',
    stopping: 'warning'
  }
  return types[status] || 'info'
}

const getStatusText = (status) => {
  const texts = {
    initializing: '初始化',
    starting: '启动中',
    preparing: '准备中',
    running: '运行中',
    completed: '已完成',
    failed: '失败',
    stopped: '已强制停止',
    stopping: '停止中'
  }
  return texts[status] || status
}

const formatTime = (timestamp) => {
  if (!timestamp) return '-'
  return new Date(timestamp * 1000).toLocaleString('zh-CN')
}

onMounted(() => {
  loadFileList()
  loadTasks()
  // 保持每 3 秒的高频轮询，驱动日志和状态的动画效果
  refreshTimer = setInterval(() => {
    loadTasks()
  }, 3000)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>

<style scoped>
.replay-page {
  max-width: 1400px;
  margin: 0 auto;
}

.tasks-card {
  margin-top: 20px;
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.card-header h3 {
  margin: 0;
}

/* 终端界面 CSS */
.terminal-container {
  background-color: #121212;
  color: #00ff00; /* 经典的黑客绿 */
  font-family: 'Consolas', 'Courier New', Courier, monospace;
  padding: 15px;
  height: 350px;
  overflow-y: auto;
  border-radius: 6px;
  box-shadow: inset 0 0 10px rgba(0,0,0,0.8);
  border: 1px solid #333;
}

.terminal-container::-webkit-scrollbar {
  width: 8px;
}
.terminal-container::-webkit-scrollbar-thumb {
  background-color: #333;
  border-radius: 4px;
}

.terminal-line {
  line-height: 1.6;
  font-size: 13px;
  word-break: break-all;
  margin-bottom: 2px;
}

.prompt {
  color: #00bcd4; /* 命令提示符用青色区分 */
  font-weight: bold;
  margin-right: 8px;
}

.terminal-empty {
  color: #888;
  font-style: italic;
  animation: blink 1.5s infinite;
}

@keyframes blink {
  0% { opacity: 1; }
  50% { opacity: 0.4; }
  100% { opacity: 1; }
}
</style>