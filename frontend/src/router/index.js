import { createRouter, createWebHistory } from 'vue-router'
import Home from '../views/Home.vue'
import Upload from '../views/Upload.vue'
import Analysis from '../views/Analysis.vue'
import Replay from '../views/Replay.vue'

const routes = [
  {
    path: '/',
    name: 'Home',
    component: Home
  },
  {
    path: '/upload',
    name: 'Upload',
    component: Upload
  },
  {
    path: '/analysis',
    name: 'Analysis',
    component: Analysis
  },
  {
    path: '/replay',
    name: 'Replay',
    component: Replay
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
