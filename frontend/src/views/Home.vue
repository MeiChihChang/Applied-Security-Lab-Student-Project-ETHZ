<template>
  <div class="home">
    
<div class="bgimg">
  <div class="topleft">
  </div>
  <div class="middle">
    <h1>Wellcome to iMovies CERT page</h1>
    <hr>
    <template v-if="authenticated">
      <template v-if="admin">
        <router-link :to="{ name: 'admin' }"> CA Administration </router-link>
      </template>
      <router-link :to="{ name: 'dashboard' }"> Dashboard </router-link>
    </template>
    <template v-else>
      <router-link :to="{ name: 'login' }"> Login </router-link>
    </template>
  </div>
  <div class="bottomleft">
  </div>
</div>


  </div>
</template>

<script>
import { mapGetters } from "vuex";
export default {
  name: 'Home',
  components: {
    //
  },
  computed: {
    ...mapGetters({
      authenticated: "auth/authenticated",
      admin: "auth/admin",
    }),
  },
}
</script>

<style scoped>
a {
  display: block;
  color: white;
  text-align: center;
  padding: 16px;
  text-decoration: none;
  background-color: #7c7c7c5d;
  margin: 10px;
}
a:hover {
  background-color: #111111;
}
/* Set height to 100% for body and html to enable the background image to cover the whole page: */
.home {
  height: calc(100vh - 51px);
  display: block;
}

.bgimg {
  /* Background image */
  /* Full-screen */
  height: 100%;
  /* Center the background image */
  background-position: center;
  /* Scale and zoom in the image */
  background-size: cover;
  /* Add position: relative to enable absolutely positioned elements inside the image (place text) */
  position: relative;
  /* Add a white text color to all elements inside the .bgimg container */
  color: white;
  /* Add a font */
  font-family: "Courier New", Courier, monospace;
  /* Set the font-size to 25 pixels */
  font-size: 25px;
}

/* Position text in the top-left corner */
.topleft {
  position: absolute;
  top: 0;
  left: 16px;
}

/* Position text in the bottom-left corner */
.bottomleft {
  position: absolute;
  bottom: 0;
  left: 16px;
}

/* Position text in the middle */
.middle {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  text-align: center;
}

/* Style the <hr> element */
hr {
  margin: auto;
  width: 40%;
}
</style>