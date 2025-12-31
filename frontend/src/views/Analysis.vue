<template>
  <div class="analysis-page">

    <el-card class="file-list-card">
      <template #header>
        <div class="card-header">
          <h2>🛡️ 流量文件列表</h2>
          <el-button type="primary" link @click="loadFileList">
            <el-icon>
              <Refresh />
            </el-icon> 刷新列表
          </el-button>
        </div>
      </template>

      <el-table :data="pcapFiles" stripe style="width: 100%" :row-class-name="tableRowClassName">
        <el-table-column label="文件名" min-width="200">
          <template #default="scope">
            <el-icon style="vertical-align: -2px; margin-right: 8px">
              <Document />
            </el-icon>
            <span style="font-weight: 500; font-size: 15px;">{{ scope.row.filename }}</span>
          </template>
        </el-table-column>

        <el-table-column prop="upload_time" label="上传时间" width="220" align="center">
          <template #default="scope">
            <div style="display: flex; align-items: center; justify-content: center; color: #606266;">
              <el-icon style="margin-right: 4px;">
                <Timer />
              </el-icon>
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
            <el-button type="primary" size="small" :icon="VideoPlay"
              :loading="analyzing && selectedFileId === scope.row.file_id"
              :disabled="analyzing && selectedFileId !== scope.row.file_id" @click="handleAnalyze(scope.row)">
              {{ (analyzing && selectedFileId === scope.row.file_id) ? '分析中...' : '开始分析' }}
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-alert v-if="statistics && currentFileName" :title="`当前分析报告: ${currentFileName}`" type="success"
      :closable="false" show-icon style="margin-top: 20px;" />

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
import { ref, onMounted, nextTick, watch, computed, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Document, VideoPlay, Refresh, Timer } from '@element-plus/icons-vue'
import * as echarts from 'echarts'
import api from '../api'

const route = useRoute()
const pcapFiles = ref([])
const selectedFileId = ref('')
const analyzing = ref(false)

// 数据响应式变量
const analysisData = ref(null)
const statistics = ref(null)
const attackPathData = ref(null)
const timelineData = ref(null)

// ECharts DOM 引用
const attackPathChart = ref(null)
const protocolChart = ref(null)
const timelineChart = ref(null)

// ECharts 实例变量
let attackPathChartInstance = null
let protocolChartInstance = null
let timelineChartInstance = null

// 轮询定时器
let pollingTimer = null

// 计算属性：当前文件名
const currentFileName = computed(() => {
  const file = pcapFiles.value.find(f => f.file_id === selectedFileId.value)
  return file ? (file.filename || file.original_name) : ''
})

// === 1. 关键修复：销毁旧图表实例 ===
const disposeCharts = () => {
  if (attackPathChartInstance) {
    attackPathChartInstance.dispose()
    attackPathChartInstance = null
  }
  if (protocolChartInstance) {
    protocolChartInstance.dispose()
    protocolChartInstance = null
  }
  if (timelineChartInstance) {
    timelineChartInstance.dispose()
    timelineChartInstance = null
  }
}

// 加载文件列表
const loadFileList = async () => {
  try {
    const result = await api.listPcaps()
    pcapFiles.value = Array.isArray(result) ? result : (result.files || [])

    // URL 参数自动选中
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
  return row.file_id === selectedFileId.value ? 'success-row' : ''
}

// 点击分析按钮
const handleAnalyze = async (row) => {
  if (analyzing.value && selectedFileId.value === row.file_id) return
  selectedFileId.value = row.file_id
  await startAnalysis()
}

// === 2. 核心逻辑：开始分析 ===
const startAnalysis = async () => {
  if (!selectedFileId.value) return

  // A. 先销毁旧图表！防止复用导致的空白
  disposeCharts()

  // B. 重置数据
  analysisData.value = null
  statistics.value = null
  attackPathData.value = null
  timelineData.value = null
  analyzing.value = true

  // C. 清除旧定时器
  if (pollingTimer) clearInterval(pollingTimer)

  try {
    // D. 提交任务
    const res = await api.analyzeTraffic(selectedFileId.value)
    if (res.task_id) {
      ElMessage.success('任务提交成功，正在后台分析...')
      startPolling(res.task_id)
    } else {
      throw new Error('未获取到任务ID')
    }
  } catch (error) {
    ElMessage.error('分析请求失败: ' + (error.response?.data?.detail || error.message))
    analyzing.value = false
  }
}

// === 3. 轮询状态 ===
const startPolling = (taskId) => {
  pollingTimer = setInterval(async () => {
    try {
      const statusRes = await api.getAnalysisStatus(taskId)

      if (statusRes.status === 'completed') {
        clearInterval(pollingTimer)
        pollingTimer = null
        handleAnalysisComplete(statusRes.result)

      } else if (statusRes.status === 'failed') {
        clearInterval(pollingTimer)
        pollingTimer = null
        analyzing.value = false
        ElMessage.error('分析任务失败: ' + (statusRes.error || '未知错误'))
      } else {
        // console.log('分析进行中...')
      }
    } catch (error) {
      clearInterval(pollingTimer)
      pollingTimer = null
      analyzing.value = false
      ElMessage.error('获取任务状态出错')
    }
  }, 2000)
}

// === 4. 处理完成数据 ===
const handleAnalysisComplete = async (fullResult) => {
  try {
    analyzing.value = false
    ElMessage.success('分析完成！')

    // 1. 赋值核心数据
    analysisData.value = fullResult
    statistics.value = fullResult.statistics
    
    // 2. 攻击路径
    if (fullResult.attack_path && fullResult.attack_path.nodes) {
        attackPathData.value = fullResult.attack_path
    }
    
    // 3. [关键修改] 直接使用后端返回的时间线，不再单独请求
    if (fullResult.timeline) {
        timelineData.value = fullResult.timeline
    } else {
        // 如果万一后端没返回，再尝试降级方案（通常不会走到这）
        try {
          const timelineRes = await api.getTimeline(selectedFileId.value)
          timelineData.value = timelineRes
        } catch (e) {
          console.warn('时间线获取失败', e)
        }
    }

    // 4. 渲染图表
    await nextTick()
    renderCharts()
  } catch (e) {
    console.error('数据处理异常', e)
    ElMessage.error('结果渲染失败')
  }
}

// === 5. 渲染图表函数 ===
const renderCharts = () => {
  renderAttackPathChart()
  renderProtocolChart()
  renderTimelineChart()
}

const renderAttackPathChart = () => {
  if (!attackPathChart.value || !attackPathData.value) return
  // 初始化实例
  if (!attackPathChartInstance) attackPathChartInstance = echarts.init(attackPathChart.value)

  const option = {
    title: { text: '网络攻击路径图', left: 'center' },
    tooltip: { formatter: (params) => params.dataType === 'edge' ? `${params.data.source} → ${params.data.target}<br/>数据包: ${params.data.value}` : params.data.name },
    legend: [{
      data: attackPathData.value.categories ? attackPathData.value.categories.map(c => c.name) : [],
      bottom: 10
    }],
    series: [{
      type: 'graph',
      layout: 'force',
      data: attackPathData.value.nodes,
      links: attackPathData.value.links,
      categories: attackPathData.value.categories,
      roam: true,
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
  
  // 1. 数据准备：依然生成完整的“年月日 时分秒”字符串
  // 这样 Tooltip 才能拿到完整时间
  const times = timeline.map(t => {
    const date = new Date(t.time * 1000)
    const Y = date.getFullYear() + '-'
    const M = (date.getMonth() + 1).toString().padStart(2, '0') + '-'
    const D = date.getDate().toString().padStart(2, '0')
    const h = date.getHours().toString().padStart(2, '0') + ':'
    const m = date.getMinutes().toString().padStart(2, '0') + ':'
    const s = date.getSeconds().toString().padStart(2, '0')
    return `${Y}${M}${D} ${h}${m}${s}` // 例如: 2023-12-16 10:16:45
  })

  const packets = timeline.map(t => t.packets)
  
  const option = {
    title: { text: '流量时间线', left: 'center' },
    
    // 2. 悬浮提示：显示完整时间
    tooltip: { 
        trigger: 'axis',
        // {b} 代表类目名（也就是上面的完整时间字符串）
        formatter: '{b}<br />数据包数量: {c}' 
    },
    
    // 3. 布局调整：不需要预留底部90px了，改为自动包含标签
    grid: {
        left: '3%',
        right: '4%',
        bottom: '3%',
        containLabel: true // 关键：自动计算边距，防止文字被切
    },
    
    xAxis: { 
      type: 'category', 
      data: times,
      boundaryGap: false, // 让折线从最左侧开始，不留白
      axisLabel: {
        rotate: 0,       // 改回水平显示，不倾斜
        interval: 'auto', // 自动隐藏过密的标签
        
        // 4. 关键优化：格式化轴标签，只显示“时:分:秒”
        formatter: function (value) {
            // value 是 "2023-12-16 10:16:45"
            // 我们按空格切分，取第二部分 "10:16:45"
            return value.split(' ')[1]; 
        }
      },
      axisLine: { lineStyle: { color: '#666' } } // 轴线颜色变淡一点
    },
    
    yAxis: { 
      type: 'value', 
      name: '数据包/秒',
      splitLine: { lineStyle: { type: 'dashed' } } // 网格线改虚线，更清爽
    },
    
    series: [{ 
      data: packets, 
      type: 'line', 
      smooth: true,      // 平滑曲线
      symbol: 'none',    // 去掉折线上的小圆点，让线条更流畅（鼠标放上去才会显示点）
      itemStyle: { color: '#409EFF' },
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: 'rgba(64, 158, 255, 0.5)' },
          { offset: 1, color: 'rgba(64, 158, 255, 0.05)' } // 渐变到底部更淡
        ])
      }
    }]
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

// === 6. 销毁逻辑：离开页面时清理 ===
onUnmounted(() => {
  if (pollingTimer) clearInterval(pollingTimer)
  disposeCharts()
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

.stats-card,
.chart-card,
.flow-card {
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