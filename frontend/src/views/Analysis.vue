<template>
  <div class="analysis-dashboard" v-loading="isAnalyzing" :element-loading-text="loadingText">
    
    <div class="toolbar">
      <span class="toolbar-label">选择流量包:</span>
      <el-select 
        v-model="selectedFileId" 
        placeholder="请选择要分析的 PCAP 文件" 
        size="small" 
        style="width: 300px; margin-right: 20px;"
        @change="handleFileChange"
      >
        <el-option
          v-for="file in pcapFiles"
          :key="file.file_id"
          :label="file.file_name || file.file_id"
          :value="file.file_id"
        />
      </el-select>

      <!-- FIX: Added :disabled for tabs without time field, and @change to reset on picker clear -->
      <el-date-picker
        v-model="timeRange"
        type="datetimerange"
        range-separator="至"
        start-placeholder="开始时间"
        end-placeholder="结束时间"
        size="small"
        :disabled="activeTab === 'protocols' || activeTab === 'nodes'"
        @change="handleTimeRangeChange"
      />

      <!-- FIX: Added @click handler to the 确定 button -->
      <el-button type="primary" size="small" style="margin-left: 10px;" @click="applyTimeFilter">确定</el-button>
    </div>

    <el-card shadow="never" class="chart-section" body-style="padding: 10px;">
      <div class="chart-header">
        <span class="title">流量趋势与告警分布</span>
        <div class="legends">
          <span class="legend-item"><i class="dot blue"></i> 总流量</span>
        </div>
      </div>
      <div ref="timelineChart" style="height: 250px; width: 100%;"></div>
    </el-card>

    <el-card shadow="never" class="table-section" body-style="padding: 0;">
      <el-tabs v-model="activeTab" class="custom-tabs">
        <el-tab-pane label="IP 会话 (Flows)" name="flows"></el-tab-pane>
        <el-tab-pane label="网络协议" name="protocols"></el-tab-pane>
        <el-tab-pane label="活跃端点 (Top IPs)" name="nodes"></el-tab-pane>
        <el-tab-pane label="威胁告警" name="threats"></el-tab-pane>
      </el-tabs>

      <div class="table-toolbar">
        <!-- FIX: Swapped label logic — show correct state -->
        <el-button size="small" plain @click="toggleTopLimit">
          {{ isTop1000 ? 'Top 1000 ✓ (点击显示全部)' : '显示全部 (点击切换 Top 1000)' }}
        </el-button>
        <el-button size="small" type="success" plain @click="exportToCSV">
          导出当前数据 (CSV)
        </el-button>
        <span class="filter-text">当前视图: {{ activeTabName }} | 共 {{ currentTableData.length }} 条记录</span>
      </div>

      <el-table v-if="activeTab === 'flows'" :data="currentTableData" size="small" border stripe height="400" class="dense-table">
        <el-table-column type="index" label="序号" width="60" align="center" />
        <el-table-column prop="src_ip" label="源端点 (IP)" width="150" sortable />
        <el-table-column prop="src_port" label="源端口" width="100" />
        <el-table-column prop="dst_ip" label="目的端点 (IP)" width="150" sortable />
        <el-table-column prop="dst_port" label="目的端口" width="100" />
        <el-table-column prop="protocol" label="网络协议" width="100" sortable align="center" />
        <el-table-column prop="packets" label="包数量" width="120" sortable align="right" />
        <el-table-column prop="bytes" label="总字节" width="120" sortable align="right">
          <template #default="{ row }">{{ formatBytes(row.bytes) }}</template>
        </el-table-column>
        <el-table-column label="命中的威胁规则" min-width="150">
          <template #default="{ row }">
            <el-tag v-for="t in row.threats" :key="t" size="small" type="danger" style="margin-right: 4px;">{{ t }}</el-tag>
            <span v-if="!row.threats || row.threats.length === 0" style="color: #999;">无</span>
          </template>
        </el-table-column>
      </el-table>

      <el-table v-if="activeTab === 'protocols'" :data="currentTableData" size="small" border stripe height="400" class="dense-table">
        <el-table-column type="index" label="序号" width="60" align="center" />
        <el-table-column prop="name" label="协议名称" width="200" sortable />
        <el-table-column prop="value" label="数据包数量" sortable />
        <el-table-column label="占比" width="300">
          <template #default="{ row }">
            <el-progress :percentage="calculatePercentage(row.value, protocolsData)" />
          </template>
        </el-table-column>
      </el-table>

      <el-table v-if="activeTab === 'nodes'" :data="currentTableData" size="small" border stripe height="400" class="dense-table">
        <el-table-column type="index" label="序号" width="60" align="center" />
        <el-table-column prop="ip" label="IP 地址" min-width="200" sortable />
        <el-table-column prop="packets" label="发包数量" sortable align="right" />
      </el-table>

      <el-table v-if="activeTab === 'threats'" :data="currentTableData" size="small" border stripe height="400" class="dense-table">
        <el-table-column type="index" label="序号" width="60" align="center" />
        <el-table-column prop="time" label="触发时间" width="180" sortable>
          <template #default="{ row }">{{ formatTimeLong(row.time) }}</template>
        </el-table-column>
        <el-table-column prop="threat_type" label="告警类型" width="200" sortable>
          <template #default="{ row }"><el-tag type="danger">{{ row.threat_type }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="src_ip" label="攻击源 IP" width="150" />
        <el-table-column prop="dst_ip" label="受害者 IP" width="150" />
        <el-table-column prop="port" label="目标端口" width="100" />
        <el-table-column prop="protocol" label="协议" width="100" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, shallowRef, nextTick, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import * as echarts from 'echarts'
import api from '../api' 

const route = useRoute()
const router = useRouter()
const pcapFiles = ref([])
const selectedFileId = ref('')
const activeTab = ref('flows')
const isTop1000 = ref(true)

// 图表与数据容器
const timelineChart = shallowRef(null)
const chartInstance = shallowRef(null)
const flowsData = ref([])
const protocolsData = ref([])
const nodesData = ref([])
const threatsData = ref([])

const isAnalyzing = ref(false)
const loadingText = ref('正在准备分析引擎...')

// FIX 1: Declare timeRange ref (was missing entirely)
const timeRange = ref([])

// FIX 2: Track whether user has actively applied a time filter
const isTimeFilterActive = ref(false)

// 计算属性：当前激活的标签页名称
const activeTabName = computed(() => {
  const names = { flows: 'IP 会话', protocols: '网络协议', nodes: '活跃端点', threats: '威胁告警' }
  return names[activeTab.value]
})

// FIX 3: currentTableData now applies time range filter for flows and threats
const currentTableData = computed(() => {
  let data = []
  if (activeTab.value === 'flows') data = flowsData.value
  else if (activeTab.value === 'protocols') data = protocolsData.value
  else if (activeTab.value === 'nodes') data = nodesData.value
  else if (activeTab.value === 'threats') data = threatsData.value

  // Apply time filter only for tabs that have a time field
  if (
    isTimeFilterActive.value &&
    timeRange.value &&
    timeRange.value[0] &&
    timeRange.value[1] &&
    (activeTab.value === 'flows' || activeTab.value === 'threats')
  ) {
    const start = timeRange.value[0].getTime() / 1000
    const end = timeRange.value[1].getTime() / 1000
    data = data.filter(row => row.time >= start && row.time <= end)
  }

  return isTop1000.value ? data.slice(0, 1000) : data
})

const toggleTopLimit = () => {
  isTop1000.value = !isTop1000.value
}

// FIX 4: applyTimeFilter — called when 确定 button is clicked
const applyTimeFilter = () => {
  if (!timeRange.value || !timeRange.value[0] || !timeRange.value[1]) {
    ElMessage.warning('请先选择时间范围')
    return
  }
  if (activeTab.value === 'protocols' || activeTab.value === 'nodes') {
    ElMessage.info('当前标签页不支持时间筛选')
    return
  }
  isTimeFilterActive.value = true
  ElMessage.success(`已筛选: ${timeRange.value[0].toLocaleString('zh-CN')} 至 ${timeRange.value[1].toLocaleString('zh-CN')}`)
}

// FIX 5: When date picker is cleared, reset the filter
const handleTimeRangeChange = (val) => {
  if (!val) {
    isTimeFilterActive.value = false
    ElMessage.info('时间筛选已清除')
  }
}

// 辅助工具：计算协议占比
const calculatePercentage = (val, dataArray) => {
  const total = dataArray.reduce((sum, item) => sum + item.value, 0)
  return total === 0 ? 0 : Number(((val / total) * 100).toFixed(1))
}

const formatBytes = (bytes) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

const formatTime = (timestamp) => {
  const date = new Date(timestamp * 1000)
  return date.toTimeString().split(' ')[0]
}

const formatTimeLong = (timestamp) => {
  return new Date(timestamp * 1000).toLocaleString('zh-CN')
}

// 纯前端 CSV 导出逻辑
const exportToCSV = () => {
  if (currentTableData.value.length === 0) {
    ElMessage.warning('当前视图没有可导出的数据')
    return
  }

  let csvContent = '\uFEFF'
  const keys = Object.keys(currentTableData.value[0]).filter(k => k !== 'threats')
  csvContent += keys.join(',') + '\r\n'

  currentTableData.value.forEach(row => {
    let rowData = keys.map(key => `"${row[key] || ''}"`).join(',')
    csvContent += rowData + '\r\n'
  })

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(blob)
  link.download = `分析报告_${activeTab.value}_${new Date().getTime()}.csv`
  link.click()
  URL.revokeObjectURL(link.href)
  ElMessage.success('报告导出成功')
}

// 动态渲染 ECharts 图表
const renderChart = (timelineData) => {
  if (!chartInstance.value) chartInstance.value = echarts.init(timelineChart.value)

  const timeAxis = []
  const bandwidthAxis = []
  
  timelineData.forEach(item => {
    timeAxis.push(formatTime(item.time))
    bandwidthAxis.push(((item.bytes * 8) / 1024).toFixed(2))
  })

  const option = {
    tooltip: { trigger: 'axis', formatter: '{b}<br/>{a}: {c} Kbps' },
    grid: { top: 30, left: 60, right: 30, bottom: 40 },
    xAxis: { type: 'category', boundaryGap: false, data: timeAxis },
    yAxis: { type: 'value', name: '流量 (Kbps)', splitLine: { lineStyle: { type: 'dashed', color: '#eee' } } },
    dataZoom: [ { type: 'slider', show: true, bottom: 0, height: 20 }, { type: 'inside' } ],
    series: [{
      name: '总流量', type: 'line', smooth: true, symbol: 'none',
      itemStyle: { color: '#00bcd4' },
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: 'rgba(0, 188, 212, 0.5)' }, { offset: 1, color: 'rgba(0, 188, 212, 0.1)' }])
      },
      data: bandwidthAxis
    }]
  }
  chartInstance.value.setOption(option)
}

const pollTaskStatus = async (taskId) => {
  try {
    const statusData = await api.getAnalysisStatus(taskId)
    
    if (statusData.status === 'completed') {
      isAnalyzing.value = false
      const result = statusData.result
      
      if (result.flows?.top_flows) flowsData.value = result.flows.top_flows
      if (result.threat_alerts) threatsData.value = result.threat_alerts
      if (result.protocols?.protocol_distribution) protocolsData.value = result.protocols.protocol_distribution
      if (result.statistics?.top_talkers) nodesData.value = result.statistics.top_talkers
      
      if (result.timeline?.timeline) {
        await nextTick() 
        renderChart(result.timeline.timeline)
        const timelineArr = result.timeline.timeline
        if (timelineArr.length > 0) {
          const startTime = new Date(timelineArr[0].time * 1000)
          const endTime = new Date(timelineArr[timelineArr.length - 1].time * 1000)
          timeRange.value = [startTime, endTime]
          // FIX: Don't auto-activate filter on data load, let user decide
          isTimeFilterActive.value = false
        }
      }
      ElMessage.success('流量分析完成！')
    } else if (statusData.status === 'failed') {
      isAnalyzing.value = false
      ElMessage.error('分析失败: ' + (statusData.error || '后端解析异常'))
    } else {
      loadingText.value = '正在进行深度包检测 (DPI)...'
      setTimeout(() => pollTaskStatus(taskId), 2000)
    }
  } catch (error) {
    isAnalyzing.value = false
    ElMessage.error('轮询状态异常，已断开')
  }
}

const runAnalysis = async (fileId) => {
  isAnalyzing.value = true
  loadingText.value = '正在向分析引擎下发任务...'
  
  // 清理旧数据
  flowsData.value = []; protocolsData.value = []; nodesData.value = []; threatsData.value = [];
  isTimeFilterActive.value = false
  
  try {
    const res = await api.startAnalysis(fileId, 'full')
    pollTaskStatus(res.task_id)
  } catch (error) {
    isAnalyzing.value = false
    ElMessage.error('提交分析任务失败')
  }
}

const loadFileList = async () => {
  try {
    const result = await api.listPcaps()
    const files = result.files || result || []
    pcapFiles.value = files.map(f => ({
      file_id: f.file_id || f.id || f.fileId || f,
      file_name: f.filename || f.file_name || f
    }))
  } catch (error) {
    ElMessage.error('加载流量包列表失败')
  }
}

const handleFileChange = (newFileId) => {
  if (!newFileId) return
  router.replace({ query: { ...route.query, fileId: newFileId } })
  if (chartInstance.value) chartInstance.value.clear()
  runAnalysis(newFileId)
}

onMounted(async () => {
  await loadFileList()
  const fileId = route.query.fileId || route.params.fileId
  if (fileId) {
    selectedFileId.value = fileId
    runAnalysis(fileId)
  } else if (pcapFiles.value.length > 0) {
    selectedFileId.value = pcapFiles.value[0].file_id
    runAnalysis(selectedFileId.value)
  }
  window.addEventListener('resize', () => {
    if (chartInstance.value) chartInstance.value.resize()
  })
})
</script>

<style scoped>
.analysis-dashboard { background-color: #f0f2f5; padding: 10px; font-family: sans-serif; }
.toolbar { background: #fff; padding: 8px 15px; margin-bottom: 10px; border-bottom: 2px solid #3f51b5; }
.chart-section { margin-bottom: 10px; }
.chart-header { display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 10px; }
.legends .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }
.dot.blue { background-color: #00bcd4; }
.custom-tabs :deep(.el-tabs__header) { margin: 0; background-color: #fafafa; border-bottom: 1px solid #ddd; }
.custom-tabs :deep(.el-tabs__item) { height: 32px; line-height: 32px; font-size: 12px; }
.table-toolbar { padding: 8px 10px; background-color: #f8f9fa; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 10px; }
.toolbar-label { margin-right: 10px; font-size: 14px; font-weight: bold; color: #333; }
.filter-text { margin-left: auto; font-size: 12px; color: #666; }
.dense-table { font-size: 12px; }
.dense-table :deep(.el-table__cell) { padding: 4px 0; }
</style>