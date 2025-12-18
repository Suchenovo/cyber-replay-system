import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
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
  // PCAP管理
  uploadPcap(file) {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/pcap/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
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
  
  // 流量分析
  analyzeTraffic(fileId, analysisType = 'full') {
    return api.post('/analysis/analyze', { file_id: fileId, analysis_type: analysisType })
  },
  
  getAttackPath(fileId) {
    return api.get(`/analysis/${fileId}/attack-path`)
  },
  
  getStatistics(fileId) {
    return api.get(`/analysis/${fileId}/statistics`)
  },
  
  getTimeline(fileId) {
    return api.get(`/analysis/${fileId}/timeline`)
  },
  
  // 流量重放
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
