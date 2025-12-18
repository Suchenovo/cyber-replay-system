<template>
  <div class="home">
    <el-card class="welcome-card">
      <h2>欢迎使用网络攻击复现与分析系统</h2>
      <p>本系统提供PCAP流量包上传、分析和沙箱重放功能，帮助您可视化展示攻击路径</p>
      
      <el-row :gutter="20" class="feature-cards">
        <el-col :span="8">
          <el-card shadow="hover" class="feature-card">
            <template #header>
              <el-icon :size="40"><Upload /></el-icon>
              <h3>上传PCAP文件</h3>
            </template>
            <p>支持上传.pcap、.pcapng等格式的流量包文件</p>
            <el-button type="primary" @click="$router.push('/upload')">
              开始上传
            </el-button>
          </el-card>
        </el-col>
        
        <el-col :span="8">
          <el-card shadow="hover" class="feature-card">
            <template #header>
              <el-icon :size="40"><DataAnalysis /></el-icon>
              <h3>流量分析</h3>
            </template>
            <p>深度分析流量特征，识别攻击路径和异常行为</p>
            <el-button type="success" @click="$router.push('/analysis')">
              查看分析
            </el-button>
          </el-card>
        </el-col>
        
        <el-col :span="8">
          <el-card shadow="hover" class="feature-card">
            <template #header>
              <el-icon :size="40"><VideoPlay /></el-icon>
              <h3>流量重放</h3>
            </template>
            <p>在隔离的沙箱环境中安全重放网络流量</p>
            <el-button type="warning" @click="$router.push('/replay')">
              流量重放
            </el-button>
          </el-card>
        </el-col>
      </el-row>
    </el-card>
    
    <el-card class="stats-card" v-if="stats">
      <template #header>
        <h3>系统统计</h3>
      </template>
      <el-row :gutter="20">
        <el-col :span="8">
          <div class="stat-item">
            <div class="stat-value">{{ stats.totalFiles }}</div>
            <div class="stat-label">PCAP文件数</div>
          </div>
        </el-col>
        <el-col :span="8">
          <div class="stat-item">
            <div class="stat-value">{{ stats.totalTasks }}</div>
            <div class="stat-label">重放任务数</div>
          </div>
        </el-col>
        <el-col :span="8">
          <div class="stat-item">
            <div class="stat-value">{{ stats.runningTasks }}</div>
            <div class="stat-label">运行中任务</div>
          </div>
        </el-col>
      </el-row>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Upload, DataAnalysis, VideoPlay } from '@element-plus/icons-vue'
import api from '../api'

const stats = ref(null)

const loadStats = async () => {
  try {
    const [files, tasks] = await Promise.all([
      api.listPcaps(),
      api.listReplayTasks()
    ])
    
    stats.value = {
      totalFiles: files.files?.length || 0,
      totalTasks: tasks.tasks?.length || 0,
      runningTasks: tasks.tasks?.filter(t => t.status === 'running').length || 0
    }
  } catch (error) {
    console.error('Failed to load stats:', error)
  }
}

onMounted(() => {
  loadStats()
})
</script>

<style scoped>
.home {
  max-width: 1400px;
  margin: 0 auto;
}

.welcome-card {
  margin-bottom: 20px;
  text-align: center;
}

.welcome-card h2 {
  color: #303133;
  margin-bottom: 10px;
}

.welcome-card > p {
  color: #606266;
  margin-bottom: 30px;
}

.feature-cards {
  margin-top: 30px;
}

.feature-card {
  text-align: center;
  height: 100%;
}

.feature-card .el-card__header {
  padding: 30px 20px;
}

.feature-card h3 {
  margin: 15px 0 0 0;
  color: #303133;
}

.feature-card p {
  color: #606266;
  margin: 15px 0;
  min-height: 40px;
}

.stats-card {
  margin-top: 20px;
}

.stat-item {
  text-align: center;
  padding: 20px;
}

.stat-value {
  font-size: 36px;
  font-weight: bold;
  color: #409eff;
  margin-bottom: 10px;
}

.stat-label {
  font-size: 14px;
  color: #909399;
}
</style>
