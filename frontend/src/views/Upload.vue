<template>
  <div class="upload-page">
    <el-card>
      <template #header>
        <h2>上传PCAP文件</h2>
      </template>
      
      <el-upload
        class="upload-area"
        drag
        :action="uploadUrl"
        :on-success="handleUploadSuccess"
        :on-error="handleUploadError"
        :before-upload="beforeUpload"
        :show-file-list="false"
        accept=".pcap,.pcapng,.cap"
      >
        <el-icon class="el-icon--upload"><UploadFilled /></el-icon>
        <div class="el-upload__text">
          将PCAP文件拖到此处，或<em>点击上传</em>
        </div>
        <template #tip>
          <div class="el-upload__tip">
            支持 .pcap, .pcapng, .cap 格式文件
          </div>
        </template>
      </el-upload>
    </el-card>
    
    <el-card class="file-list-card" v-if="pcapFiles.length > 0">
      <template #header>
        <div class="card-header">
          <h3>已上传文件列表</h3>
          <el-button @click="refreshFileList" :icon="Refresh">刷新</el-button>
        </div>
      </template>
      
      <el-table :data="pcapFiles" stripe>
        <el-table-column prop="file_id" label="文件ID" width="280" />
        <el-table-column prop="filename" label="文件名" />
        <el-table-column label="大小" width="120">
          <template #default="{ row }">
            {{ formatFileSize(row.size) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="300">
          <template #default="{ row }">
            <el-button size="small" type="primary" @click="viewInfo(row.file_id)">
              查看详情
            </el-button>
            <el-button size="small" type="success" @click="analyzeFile(row.file_id)">
              分析
            </el-button>
            <el-button size="small" type="danger" @click="deleteFile(row.file_id)">
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
    
    <!-- 文件详情对话框 -->
    <el-dialog v-model="infoDialogVisible" title="PCAP文件详情" width="70%">
      <div v-if="currentFileInfo">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="总数据包数">
            {{ currentFileInfo.total_packets }}
          </el-descriptions-item>
          <el-descriptions-item label="持续时间">
            {{ currentFileInfo.duration?.toFixed(2) }} 秒
          </el-descriptions-item>
          <el-descriptions-item label="唯一源IP数">
            {{ currentFileInfo.unique_src_ips }}
          </el-descriptions-item>
          <el-descriptions-item label="唯一目标IP数">
            {{ currentFileInfo.unique_dst_ips }}
          </el-descriptions-item>
        </el-descriptions>
        
        <h3 style="margin-top: 20px;">协议分布</h3>
        <el-table :data="getProtocolList(currentFileInfo.protocols)" size="small">
          <el-table-column prop="protocol" label="协议" />
          <el-table-column prop="count" label="数据包数" />
        </el-table>
        
        <h3 style="margin-top: 20px;">Top 源IP</h3>
        <el-table :data="currentFileInfo.top_src_ips" size="small">
          <el-table-column prop="ip" label="IP地址" />
          <el-table-column prop="count" label="数据包数" />
        </el-table>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { UploadFilled, Refresh } from '@element-plus/icons-vue'
import api from '../api'

const router = useRouter()
const pcapFiles = ref([])
const infoDialogVisible = ref(false)
const currentFileInfo = ref(null)
const uploadUrl = '/api/pcap/upload'

const loadFileList = async () => {
  try {
    const result = await api.listPcaps()
    pcapFiles.value = result.files || []
  } catch (error) {
    ElMessage.error('加载文件列表失败')
  }
}

const refreshFileList = () => {
  loadFileList()
}

const beforeUpload = (file) => {
  const isValidType = /\.(pcap|pcapng|cap)$/i.test(file.name)
  if (!isValidType) {
    ElMessage.error('只支持 PCAP 格式文件')
    return false
  }
  
  const isLt500M = file.size / 1024 / 1024 < 500
  if (!isLt500M) {
    ElMessage.error('文件大小不能超过 500MB')
    return false
  }
  
  return true
}

const handleUploadSuccess = (response) => {
  ElMessage.success('文件上传成功')
  loadFileList()
}

const handleUploadError = () => {
  ElMessage.error('文件上传失败')
}

const formatFileSize = (bytes) => {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
  return (bytes / 1024 / 1024).toFixed(2) + ' MB'
}

const viewInfo = async (fileId) => {
  try {
    currentFileInfo.value = await api.getPcapInfo(fileId)
    infoDialogVisible.value = true
  } catch (error) {
    ElMessage.error('获取文件信息失败')
  }
}

const analyzeFile = (fileId) => {
  router.push({ path: '/analysis', query: { fileId } })
}

const deleteFile = async (fileId) => {
  try {
    await ElMessageBox.confirm('确定要删除该文件吗？', '警告', {
      type: 'warning'
    })
    
    await api.deletePcap(fileId)
    ElMessage.success('文件已删除')
    loadFileList()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('删除失败')
    }
  }
}

const getProtocolList = (protocols) => {
  if (!protocols) return []
  return Object.entries(protocols).map(([protocol, count]) => ({
    protocol,
    count
  }))
}

onMounted(() => {
  loadFileList()
})
</script>

<style scoped>
.upload-page {
  max-width: 1200px;
  margin: 0 auto;
}

.upload-area {
  margin: 20px 0;
}

.file-list-card {
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
