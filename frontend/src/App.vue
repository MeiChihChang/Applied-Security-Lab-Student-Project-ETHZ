<template>
  <div id="app">
    <Navigator/>
    <router-view/>
  </div>
</template>

<script>
import Navigator from '@/components/Navigator'

export default {
  components: {
    Navigator
  }
}
</script>