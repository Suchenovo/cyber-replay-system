<template>
  <div class="analysis-page">
    <!-- 文件选择 -->
    <el-card>
      <template #header>
        <h2>流量分析</h2>
      </template>
      
      <el-form :inline="true">
        <el-form-item label="选择PCAP文件">
          <el-select v-model="selectedFileId" placeholder="请选择文件" @change="onFileChange">
            <el-option
              v-for="file in pcapFiles"
              :key="file.file_id"
              :label="file.filename"
              :value="file.file_id"
            />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="startAnalysis" :loading="analyzing">
            开始分析
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>
    
    <!-- 统计信息 -->
    <el-card class="stats-card" v-if="statistics">
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
    
    <!-- 攻击路径图 -->
    <el-card class="chart-card" v-if="attackPathData">
      <template #header>
        <h3>攻击路径可视化</h3>
      </template>
      <div ref="attackPathChart" style="width: 100%; height: 600px;"></div>
    </el-card>
    
    <!-- 协议分布 -->
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
    
    <!-- Top流量会话 -->
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
</template>

<script setup>
import { ref, onMounted, nextTick, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
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

const loadFileList = async () => {
  try {
    const result = await api.listPcaps()
    pcapFiles.value = result.files || []
    
    // 如果URL中有fileId参数，自动选择
    if (route.query.fileId) {
      selectedFileId.value = route.query.fileId
      await startAnalysis()
    }
  } catch (error) {
    ElMessage.error('加载文件列表失败')
  }
}

const onFileChange = () => {
  analysisData.value = null
  statistics.value = null
  attackPathData.value = null
}

const startAnalysis = async () => {
  if (!selectedFileId.value) {
    ElMessage.warning('请先选择文件')
    return
  }
  
  analyzing.value = true
  
  try {
    // 并行获取分析数据
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
    
    // 渲染图表
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
  
  if (!attackPathChartInstance) {
    attackPathChartInstance = echarts.init(attackPathChart.value)
  }
  
  const option = {
    title: {
      text: '网络攻击路径图',
      left: 'center'
    },
    tooltip: {
      formatter: (params) => {
        if (params.dataType === 'edge') {
          return `${params.data.source} → ${params.data.target}<br/>数据包: ${params.data.value}`
        }
        return params.data.name
      }
    },
    legend: [{
      data: attackPathData.value.categories.map(c => c.name),
      bottom: 10
    }],
    series: [{
      type: 'graph',
      layout: 'force',
      data: attackPathData.value.nodes,
      links: attackPathData.value.links,
      categories: attackPathData.value.categories,
      roam: true,
      label: {
        show: true,
        position: 'right',
        formatter: '{b}'
      },
      labelLayout: {
        hideOverlap: true
      },
      scaleLimit: {
        min: 0.4,
        max: 2
      },
      force: {
        repulsion: 200,
        edgeLength: [100, 300]
      },
      emphasis: {
        focus: 'adjacency',
        lineStyle: {
          width: 3
        }
      }
    }]
  }
  
  attackPathChartInstance.setOption(option)
}

const renderProtocolChart = () => {
  if (!protocolChart.value || !analysisData.value) return
  
  if (!protocolChartInstance) {
    protocolChartInstance = echarts.init(protocolChart.value)
  }
  
  const protocols = analysisData.value.protocols?.protocol_distribution || []
  
  const option = {
    title: {
      text: '协议分布',
      left: 'center'
    },
    tooltip: {
      trigger: 'item',
      formatter: '{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      left: 'left'
    },
    series: [{
      type: 'pie',
      radius: '60%',
      data: protocols,
      emphasis: {
        itemStyle: {
          shadowBlur: 10,
          shadowOffsetX: 0,
          shadowColor: 'rgba(0, 0, 0, 0.5)'
        }
      }
    }]
  }
  
  protocolChartInstance.setOption(option)
}

const renderTimelineChart = () => {
  if (!timelineChart.value || !timelineData.value) return
  
  if (!timelineChartInstance) {
    timelineChartInstance = echarts.init(timelineChart.value)
  }
  
  const timeline = timelineData.value.timeline || []
  const times = timeline.map(t => new Date(t.time * 1000).toLocaleTimeString())
  const packets = timeline.map(t => t.packets)
  
  const option = {
    title: {
      text: '流量时间线',
      left: 'center'
    },
    tooltip: {
      trigger: 'axis'
    },
    xAxis: {
      type: 'category',
      data: times,
      axisLabel: {
        rotate: 45
      }
    },
    yAxis: {
      type: 'value',
      name: '数据包数'
    },
    series: [{
      data: packets,
      type: 'line',
      smooth: true,
      areaStyle: {
        color: 'rgba(64, 158, 255, 0.3)'
      }
    }]
  }
  
  timelineChartInstance.setOption(option)
}

const formatBytes = (bytes) => {
  if (!bytes) return '0 B'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MB'
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB'
}

// 监听窗口大小变化
watch(() => window.innerWidth, () => {
  attackPathChartInstance?.resize()
  protocolChartInstance?.resize()
  timelineChartInstance?.resize()
})

onMounted(() => {
  loadFileList()
  
  // 监听窗口大小变化
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
}

.stats-card {
  margin-top: 20px;
}

.stat-box {
  text-align: center;
  padding: 20px;
  background: #f5f7fa;
  border-radius: 8px;
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

.chart-card {
  margin-top: 20px;
}

.flow-card {
  margin-top: 20px;
}
</style>
