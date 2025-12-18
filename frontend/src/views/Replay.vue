<template>
  <div class="replay-page">
    <!-- 启动重放 -->
    <el-card>
      <template #header>
        <h2>流量重放</h2>
      </template>
      
      <el-form :model="replayForm" label-width="120px">
        <el-form-item label="选择PCAP文件">
          <el-select v-model="replayForm.fileId" placeholder="请选择文件">
            <el-option
              v-for="file in pcapFiles"
              :key="file.file_id"
              :label="file.filename"
              :value="file.file_id"
            />
          </el-select>
        </el-form-item>
        
        <el-form-item label="目标IP">
          <el-input
            v-model="replayForm.targetIp"
            placeholder="留空使用原始目标IP"
            clearable
          />
        </el-form-item>
        
        <el-form-item label="重放速度">
          <el-slider
            v-model="replayForm.speedMultiplier"
            :min="0.1"
            :max="10"
            :step="0.1"
            show-input
          />
          <span style="margin-left: 10px; color: #909399;">
            {{ replayForm.speedMultiplier }}x 倍速
          </span>
        </el-form-item>
        
        <el-form-item label="使用沙箱">
          <el-switch v-model="replayForm.useSandbox" />
          <span style="margin-left: 10px; color: #909399;">
            在隔离环境中安全重放
          </span>
        </el-form-item>
        
        <el-form-item>
          <el-button type="primary" @click="startReplay" :loading="starting">
            启动重放
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>
    
    <!-- 任务列表 -->
    <el-card class="tasks-card">
      <template #header>
        <div class="card-header">
          <h3>重放任务列表</h3>
          <el-button @click="refreshTasks" :icon="Refresh">刷新</el-button>
        </div>
      </template>
      
      <el-table :data="tasks" stripe>
        <el-table-column prop="task_id" label="任务ID" width="280" />
        <el-table-column label="状态" width="120">
          <template #default="{ row }">
            <el-tag
              :type="getStatusType(row.status)"
              effect="dark"
            >
              {{ getStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="进度" width="200">
          <template #default="{ row }">
            <el-progress
              :percentage="row.progress || 0"
              :status="row.status === 'failed' ? 'exception' : undefined"
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
        <el-table-column label="操作" width="180">
          <template #default="{ row }">
            <el-button
              size="small"
              type="info"
              @click="viewTaskDetail(row)"
            >
              详情
            </el-button>
            <el-button
              size="small"
              type="danger"
              @click="stopTask(row.task_id)"
              :disabled="row.status !== 'running'"
            >
              停止
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
    
    <!-- 任务详情对话框 -->
    <el-dialog v-model="detailDialogVisible" title="任务详情" width="60%">
      <el-descriptions :column="2" border v-if="currentTask">
        <el-descriptions-item label="任务ID">
          {{ currentTask.task_id }}
        </el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="getStatusType(currentTask.status)">
            {{ getStatusText(currentTask.status) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="PCAP文件">
          {{ currentTask.pcap_file }}
        </el-descriptions-item>
        <el-descriptions-item label="进度">
          {{ currentTask.progress }}%
        </el-descriptions-item>
        <el-descriptions-item label="已发送数据包">
          {{ currentTask.sent_packets }}
        </el-descriptions-item>
        <el-descriptions-item label="总数据包">
          {{ currentTask.total_packets }}
        </el-descriptions-item>
        <el-descriptions-item label="开始时间">
          {{ formatTime(currentTask.start_time) }}
        </el-descriptions-item>
        <el-descriptions-item label="结束时间">
          {{ formatTime(currentTask.end_time) }}
        </el-descriptions-item>
        <el-descriptions-item label="错误信息" :span="2" v-if="currentTask.error">
          <el-text type="danger">{{ currentTask.error }}</el-text>
        </el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import api from '../api'

const pcapFiles = ref([])
const tasks = ref([])
const starting = ref(false)
const detailDialogVisible = ref(false)
const currentTask = ref(null)

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
    pcapFiles.value = result.files || []
  } catch (error) {
    ElMessage.error('加载文件列表失败')
  }
}

const loadTasks = async () => {
  try {
    const result = await api.listReplayTasks()
    tasks.value = result.tasks || []
  } catch (error) {
    console.error('加载任务列表失败:', error)
  }
}

const refreshTasks = () => {
  loadTasks()
}

const startReplay = async () => {
  if (!replayForm.value.fileId) {
    ElMessage.warning('请选择PCAP文件')
    return
  }
  
  starting.value = true
  
  try {
    const result = await api.startReplay(
      replayForm.value.fileId,
      replayForm.value.targetIp || null,
      replayForm.value.speedMultiplier,
      replayForm.value.useSandbox
    )
    
    ElMessage.success('重放任务已启动')
    await loadTasks()
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

const viewTaskDetail = (task) => {
  currentTask.value = task
  detailDialogVisible.value = true
}

const getStatusType = (status) => {
  const types = {
    'running': 'primary',
    'completed': 'success',
    'failed': 'danger',
    'stopped': 'warning'
  }
  return types[status] || 'info'
}

const getStatusText = (status) => {
  const texts = {
    'running': '运行中',
    'completed': '已完成',
    'failed': '失败',
    'stopped': '已停止'
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
  
  // 自动刷新任务状态
  refreshTimer = setInterval(() => {
    loadTasks()
  }, 3000)
})

onUnmounted(() => {
  if (refreshTimer) {
    clearInterval(refreshTimer)
  }
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
  justify-content: space-between;
  align-items: center;
}

.card-header h3 {
  margin: 0;
}
</style>
