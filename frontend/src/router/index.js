import Vue from 'vue'
import VueRouter from 'vue-router'
import Home from '../views/Home.vue'
import Dashboard from '../views/Dashboard'
import Login from '../views/Login.vue'
import Admin from '../views/Admin.vue'
import store from '@/store'

Vue.use(VueRouter)

const routes = [
  {
    path: '/static/index.html',
    name: 'home',
    component: Home
  },
  {
    path: '/',
    name: 'home',
    component: Home
  },
  {
    path: '/index.html',
    name: 'home',
    component: Home
  },
  {
    path: '/login',
    name: 'login',
    component: Login
  },
  {
    path: '/dashboard',
    name: 'dashboard',
    component: Dashboard,
    beforeEnter: (to, from, next) => {
      if(!store.getters['auth/authenticated']) {
        return next({
          name: 'login'
        })
      }

      next()
    }
  },
  {
    path: '/admin',
    name: 'admin',
    component: Admin,
    beforeEnter: (to, from, next) => {
      if(!store.getters['auth/admin']) {
        if(store.getters['auth/authenticated']) {
          return next({
            name: 'dashboard'
          })
        } else {
          return next({
            name: 'login'
          }) 
        }
      } else {
        if(store.getters['auth/authenticated']) {
          next()
        } else {
          return next({
            name: 'login'
          })
        }
      }
    }
  },
]

const router = new VueRouter({
  mode: 'history',
  base: process.env.BASE_URL,
  routes
})

export default router
