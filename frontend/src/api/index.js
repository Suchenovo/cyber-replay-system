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

// 响应拦截器：已经在这里统一剥离了 response.data，后面的接口直接 return 即可
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
  // --- PCAP管理 ---
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
  
  // --- 流量分析 (合并清理版) ---
  
  /**
   * 1. 提交流量分析任务，返回 task_id
   */
  startAnalysis(fileId, analysisType = 'full') {
    return api.post('/analysis/analyze', { 
      file_id: fileId, 
      analysis_type: analysisType 
    })
  },

  /**
   * 2. 轮询获取分析任务状态和结果
   */
  getAnalysisStatus(taskId) {
    return api.get(`/analysis/status/${taskId}`)
  },
  
  // 3. 获取时间线 (单独获取数据的接口保留，以备不时之需)
  getTimeline(fileId) {
    return api.get(`/analysis/${fileId}/timeline`)
  },

  getAttackPath(fileId) {
    return api.get(`/analysis/${fileId}/attack-path`)
  },
  
  getStatistics(fileId) {
    return api.get(`/analysis/${fileId}/statistics`)
  },
  
  // --- 流量重放 ---
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
  },
  
  deleteReplayTask(taskId) {
    return api.delete(`/replay/${taskId}`)
  }
}