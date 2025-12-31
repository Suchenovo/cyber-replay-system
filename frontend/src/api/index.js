import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  // 注意：超时时间不需要设置特别大，因为现在请求都是立刻返回的
  timeout: 30000 
})

// 请求拦截器
api.interceptors.request.use(
  config => {
    return config
  },
  error => {
    return Promise.reject(error)
  }
)

// 响应拦截器
api.interceptors.response.use(
  response => {
    return response.data
  },
  error => {
    console.error('API Error:', error)
    return Promise.reject(error)
  }
)

export default {
  // --- PCAP管理 (保持不变) ---
  uploadPcap(file) {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/pcap/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 0 // 上传大文件特殊处理，不超时
    })
  },
  
  listPcaps() {
    return api.get('/pcap/list')
  },
  
  getPcapInfo(fileId) {
    return api.get(`/pcap/${fileId}/info`)
  },
  
  deletePcap(fileId) {
    return api.delete(`/pcap/${fileId}`)
  },
  
  // --- 流量分析 (核心修改) ---
  
  // 1. 提交分析任务 (现在返回的是 task_id)
  analyzeTraffic(fileId, analysisType = 'full') {
    return api.post('/analysis/analyze', { file_id: fileId, analysis_type: analysisType })
  },
  
  // 2. [新增] 获取分析任务状态 (用于轮询)
  getAnalysisStatus(taskId) {
    return api.get(`/analysis/status/${taskId}`)
  },
  
  // 3. 获取时间线 (后端全量分析可能未包含此数据，保留单独调用)
  getTimeline(fileId) {
    return api.get(`/analysis/${fileId}/timeline`)
  },

  // (以下单独获取数据的接口保留，以备不时之需)
  getAttackPath(fileId) {
    return api.get(`/analysis/${fileId}/attack-path`)
  },
  
  getStatistics(fileId) {
    return api.get(`/analysis/${fileId}/statistics`)
  },
  
  // --- 流量重放 (保持不变) ---
  startReplay(fileId, targetIp = null, speedMultiplier = 1.0, useSandbox = true) {
    return api.post('/replay/start', {
      file_id: fileId,
      target_ip: targetIp,
      speed_multiplier: speedMultiplier,
      use_sandbox: useSandbox
    })
  },
  
  getReplayStatus(taskId) {
    return api.post('/replay/status', { task_id: taskId })
  },
  
  stopReplay(taskId) {
    return api.post('/replay/stop', { task_id: taskId })
  },
  
  listReplayTasks() {
    return api.get('/replay/tasks')
  }
}