<template>
  <div class="analysis-page">
    
    <el-card class="file-list-card">
      <template #header>
        <div class="card-header">
          <h2>🛡️ 流量文件列表</h2>
          <el-button type="primary" link @click="loadFileList">
            <el-icon><Refresh /></el-icon> 刷新列表
          </el-button>
        </div>
      </template>
      
      <el-table 
        :data="pcapFiles" 
        stripe 
        style="width: 100%"
        :row-class-name="tableRowClassName"
      >
        <el-table-column label="文件名" min-width="200">
          <template #default="scope">
            <el-icon style="vertical-align: -2px; margin-right: 8px"><Document /></el-icon>
            <span style="font-weight: 500; font-size: 15px;">{{ scope.row.filename }}</span>
          </template>
        </el-table-column>

        <el-table-column prop="upload_time" label="上传时间" width="220" align="center">
          <template #default="scope">
             <div style="display: flex; align-items: center; justify-content: center; color: #606266;">
                <el-icon style="margin-right: 4px;"><Timer /></el-icon>
                <span>{{ scope.row.upload_time }}</span>
             </div>
          </template>
        </el-table-column>

        <el-table-column label="文件ID" min-width="250" show-overflow-tooltip>
          <template #default="scope">
            <span style="color: #909399; font-size: 13px; font-family: monospace;">
              {{ scope.row.file_id }}
            </span>
          </template>
        </el-table-column>

        <el-table-column label="操作" width="160" fixed="right" align="center">
          <template #default="scope">
            <el-button 
              type="primary" 
              size="small" 
              :icon="VideoPlay"
              :loading="analyzing && selectedFileId === scope.row.file_id"
              :disabled="analyzing && selectedFileId !== scope.row.file_id"
              @click="handleAnalyze(scope.row)"
            >
              {{ selectedFileId === scope.row.file_id ? '分析中' : '开始分析' }}
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-alert
      v-if="statistics && currentFileName"
      :title="`当前分析报告: ${currentFileName}`"
      type="success"
      :closable="false"
      show-icon
      style="margin-top: 20px;"
    />
    
    <div v-if="statistics">
      <el-card class="stats-card">
        <template #header>
          <h3>流量统计</h3>
        </template>
        <el-row :gutter="20">
          <el-col :span="6">
            <div class="stat-box">
              <div class="stat-value">{{ statistics.total_packets }}</div>
              <div class="stat-label">总数据包</div>
            </div>
          </el-col>
          <el-col :span="6">
            <div class="stat-box">
              <div class="stat-value">{{ formatBytes(statistics.total_bytes) }}</div>
              <div class="stat-label">总流量</div>
            </div>
          </el-col>
          <el-col :span="6">
            <div class="stat-box">
              <div class="stat-value">{{ statistics.duration?.toFixed(2) }}s</div>
              <div class="stat-label">持续时间</div>
            </div>
          </el-col>
          <el-col :span="6">
            <div class="stat-box">
              <div class="stat-value">{{ statistics.packets_per_second?.toFixed(0) }}</div>
              <div class="stat-label">数据包/秒</div>
            </div>
          </el-col>
        </el-row>
      </el-card>
      
      <el-card class="chart-card" v-if="attackPathData">
        <template #header>
          <h3>攻击路径可视化</h3>
        </template>
        <div ref="attackPathChart" style="width: 100%; height: 600px;"></div>
      </el-card>
      
      <el-row :gutter="20" v-if="analysisData">
        <el-col :span="12">
          <el-card class="chart-card">
            <template #header>
              <h3>协议分布</h3>
            </template>
            <div ref="protocolChart" style="width: 100%; height: 400px;"></div>
          </el-card>
        </el-col>
        
        <el-col :span="12">
          <el-card class="chart-card">
            <template #header>
              <h3>流量时间线</h3>
            </template>
            <div ref="timelineChart" style="width: 100%; height: 400px;"></div>
          </el-card>
        </el-col>
      </el-row>
      
      <el-card class="flow-card" v-if="analysisData && analysisData.flows">
        <template #header>
          <h3>Top 流量会话</h3>
        </template>
        <el-table :data="analysisData.flows.top_flows" stripe>
          <el-table-column prop="src_ip" label="源IP" width="150" />
          <el-table-column prop="src_port" label="源端口" width="100" />
          <el-table-column prop="dst_ip" label="目标IP" width="150" />
          <el-table-column prop="dst_port" label="目标端口" width="100" />
          <el-table-column prop="protocol" label="协议" width="100" />
          <el-table-column prop="packets" label="数据包数" width="120" />
          <el-table-column label="流量大小">
            <template #default="{ row }">
              {{ formatBytes(row.bytes) }}
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>
    
    <el-empty v-else description="请从上方列表选择一个文件开始分析" style="margin-top: 50px;"></el-empty>

  </div>
</template>

<script setup>
import { ref, onMounted, nextTick, watch, computed } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Document, VideoPlay, Refresh, Timer } from '@element-plus/icons-vue' 
import * as echarts from 'echarts'
import api from '../api'

const route = useRoute()
const pcapFiles = ref([])
const selectedFileId = ref('')
const analyzing = ref(false)
const analysisData = ref(null)
const statistics = ref(null)
const attackPathData = ref(null)
const timelineData = ref(null)

const attackPathChart = ref(null)
const protocolChart = ref(null)
const timelineChart = ref(null)

let attackPathChartInstance = null
let protocolChartInstance = null
let timelineChartInstance = null

// 计算属性：获取当前正在分析的文件名
const currentFileName = computed(() => {
  const file = pcapFiles.value.find(f => f.file_id === selectedFileId.value)
  return file ? (file.filename || file.original_name) : ''
})

const loadFileList = async () => {
  try {
    const result = await api.listPcaps()
    // 兼容不同的API返回格式
    pcapFiles.value = Array.isArray(result) ? result : (result.files || [])
    
    if (route.query.fileId && !selectedFileId.value) {
      const fileExists = pcapFiles.value.find(f => f.file_id === route.query.fileId)
      if (fileExists) {
        handleAnalyze(fileExists)
      }
    }
  } catch (error) {
    ElMessage.error('加载文件列表失败')
  }
}

const tableRowClassName = ({ row }) => {
  if (row.file_id === selectedFileId.value) {
    return 'success-row'
  }
  return ''
}

const handleAnalyze = async (row) => {
  if (analyzing.value && selectedFileId.value === row.file_id) return
  selectedFileId.value = row.file_id
  await startAnalysis()
}

const startAnalysis = async () => {
  if (!selectedFileId.value) return
  
  analysisData.value = null
  statistics.value = null
  attackPathData.value = null
  analyzing.value = true
  
  try {
    const [analysis, stats, attackPath, timeline] = await Promise.all([
      api.analyzeTraffic(selectedFileId.value),
      api.getStatistics(selectedFileId.value),
      api.getAttackPath(selectedFileId.value),
      api.getTimeline(selectedFileId.value)
    ])
    
    analysisData.value = analysis
    statistics.value = stats
    attackPathData.value = attackPath
    timelineData.value = timeline
    
    ElMessage.success('分析完成')
    
    await nextTick()
    renderCharts()
  } catch (error) {
    ElMessage.error('分析失败: ' + (error.response?.data?.detail || error.message))
  } finally {
    analyzing.value = false
  }
}

const renderCharts = () => {
  renderAttackPathChart()
  renderProtocolChart()
  renderTimelineChart()
}

const renderAttackPathChart = () => {
  if (!attackPathChart.value || !attackPathData.value) return
  if (!attackPathChartInstance) attackPathChartInstance = echarts.init(attackPathChart.value)
  const option = {
    title: { text: '网络攻击路径图', left: 'center' },
    tooltip: { formatter: (params) => params.dataType === 'edge' ? `${params.data.source} → ${params.data.target}<br/>数据包: ${params.data.value}` : params.data.name },
    legend: [{ data: attackPathData.value.categories.map(c => c.name), bottom: 10 }],
    series: [{
      type: 'graph', layout: 'force', data: attackPathData.value.nodes, links: attackPathData.value.links, categories: attackPathData.value.categories, roam: true,
      label: { show: true, position: 'right', formatter: '{b}' },
      force: { repulsion: 200, edgeLength: [100, 300] }
    }]
  }
  attackPathChartInstance.setOption(option)
}

const renderProtocolChart = () => {
  if (!protocolChart.value || !analysisData.value) return
  if (!protocolChartInstance) protocolChartInstance = echarts.init(protocolChart.value)
  const protocols = analysisData.value.protocols?.protocol_distribution || []
  const option = {
    title: { text: '协议分布', left: 'center' },
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    series: [{ type: 'pie', radius: '60%', data: protocols }]
  }
  protocolChartInstance.setOption(option)
}

const renderTimelineChart = () => {
  if (!timelineChart.value || !timelineData.value) return
  if (!timelineChartInstance) timelineChartInstance = echarts.init(timelineChart.value)
  const timeline = timelineData.value.timeline || []
  const times = timeline.map(t => new Date(t.time * 1000).toLocaleTimeString())
  const packets = timeline.map(t => t.packets)
  const option = {
    title: { text: '流量时间线', left: 'center' },
    tooltip: { trigger: 'axis' },
    xAxis: { type: 'category', data: times },
    yAxis: { type: 'value' },
    series: [{ data: packets, type: 'line', smooth: true, areaStyle: {} }]
  }
  timelineChartInstance.setOption(option)
}

const formatBytes = (bytes) => {
  if (!bytes && bytes !== 0) return '0 B'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MB'
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB'
}

watch(() => window.innerWidth, () => {
  attackPathChartInstance?.resize()
  protocolChartInstance?.resize()
  timelineChartInstance?.resize()
})

onMounted(() => {
  loadFileList()
  window.addEventListener('resize', () => {
    attackPathChartInstance?.resize()
    protocolChartInstance?.resize()
    timelineChartInstance?.resize()
  })
})
</script>

<style scoped>
.analysis-page {
  max-width: 1400px;
  margin: 0 auto;
  padding-bottom: 40px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header h2 {
  font-size: 18px;
  margin: 0;
  display: flex;
  align-items: center;
  gap: 8px;
}

.file-list-card {
  margin-bottom: 20px;
}

:deep(.el-table .success-row) {
  --el-table-tr-bg-color: var(--el-color-success-light-9);
}

.stats-card, .chart-card, .flow-card {
  margin-top: 20px;
}

.stat-box {
  text-align: center;
  padding: 20px;
  background: #f5f7fa;
  border-radius: 8px;
  transition: all 0.3s;
}

.stat-box:hover {
  background: #ecf5ff;
  transform: translateY(-2px);
}

.stat-value {
  font-size: 28px;
  font-weight: bold;
  color: #409eff;
  margin-bottom: 10px;
}

.stat-label {
  font-size: 14px;
  color: #909399;
}
</style>