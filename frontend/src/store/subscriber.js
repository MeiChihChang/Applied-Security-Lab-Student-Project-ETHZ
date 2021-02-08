import store from '@/store'
import axios from 'axios'

store.subscribe((mutation) => {
    switch (mutation.type) {
        case "auth/SET_TOKEN":
            if(mutation.payload) {
                axios.defaults.headers.common['Authorization'] = `${mutation.payload}` 
                localStorage.setItem('token', mutation.payload)
            } else {
                axios.defaults.headers.common['Authorization'] = null
                localStorage.removeItem('token', mutation.payload)
            }
            break;
        case "auth/SET_CERT_ID":
            if(mutation.payload) {
                localStorage.setItem('cert_id', mutation.payload)
            } else {
                localStorage.removeItem('cert_id', mutation.payload)
                localStorage.removeItem('cert', mutation.payload)
            }
            break;
        case "auth/SET_CERT":
            if(mutation.payload) {
                localStorage.setItem('cert', mutation.payload)
            } else {
                localStorage.removeItem('cert', mutation.payload)
            }
            break;
        case "auth/SET_CA_INFO":
            console.log("set_ca_info")
            break
        default:
            break;
    }
})