<template>
  <div id="app">
    <el-container class="layout-container">
      <el-header class="header">
        <div class="header-content">
          <h1>🛡️ 网络攻击复现与分析系统</h1>
          
          <el-menu 
            mode="horizontal" 
            :default-active="activeRoute" 
            router
            :ellipsis="false" 
          >
            <el-menu-item index="/">首页</el-menu-item>
            <el-menu-item index="/upload">上传PCAP</el-menu-item>
            <el-menu-item index="/analysis">流量分析</el-menu-item>
            <el-menu-item index="/replay">流量重放</el-menu-item>
          </el-menu>
        </div>
      </el-header>
      
      <el-main class="main-content">
        <router-view />
      </el-main>
    </el-container>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()
const activeRoute = computed(() => route.path)
</script>

<style>

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

#app {
  font-family: 'Helvetica Neue', Helvetica, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', Arial, sans-serif;
  height: 100vh;
}

.layout-container {
  height: 100vh;
}


.header {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  padding: 0; 
}


.header-content {
  max-width: 1400px;
  margin: 0 auto;
  padding: 0 20px;
  height: 100%;
  

  display: flex;
  align-items: center;
  justify-content: space-between; 
}

.header h1 {
  font-size: 22px; 
  font-weight: 600;
  white-space: nowrap; 
  margin-right: 40px; 
}

.header .el-menu {
  background: transparent !important; 
  border: none !important; 
  
  display: flex;
  align-items: center;
  height: 100%;
}

.header .el-menu-item {
  color: rgba(255, 255, 255, 0.85) !important; 
  border-bottom: 3px solid transparent !important; 
  font-size: 15px;
  padding: 0 20px; 
  height: 100%;
  display: flex;
  align-items: center;
  transition: all 0.3s;
}

.header .el-menu-item:hover,
.header .el-menu-item.is-active {
  color: #fff !important;
  background-color: rgba(255, 255, 255, 0.15) !important; 
  border-bottom-color: #fff !important; 
}

.header .el-menu-item:focus {
    background-color: rgba(255, 255, 255, 0.15) !important; 
}

.main-content {
  background: #f5f7fa;
  padding: 20px;
}
</style>