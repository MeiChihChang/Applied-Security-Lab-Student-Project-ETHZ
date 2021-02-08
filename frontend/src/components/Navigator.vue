<template>
  <ul>
    <li>
      <router-link :to="{ name: 'home' }"> Home </router-link>
    </li>

    <template v-if="admin">
       <li>
        <router-link :to="{ name: 'admin' }"> CA Administration </router-link>
         </li>
      </template>

    <template v-if="authenticated">
      <li>
        <router-link :to="{ name: 'dashboard' }"> Dashboard </router-link>
      </li>
      <li class="right">
        Welcome {{ user.firstname }}
      </li>
      <li   >
        <a href="#" @click.prevent="signout">Sign out</a>
      </li>
    </template>
    <template v-else>
      <li>
        <router-link :to="{ name: 'login' }"> Login </router-link>
      </li>
    </template>
  </ul>
</template>

<script>
import { mapGetters, mapActions } from "vuex";
export default {
  computed: {
    ...mapGetters({
      authenticated: "auth/authenticated",
      user: "auth/user",
      admin: "auth/admin"
    }),
  },

  methods: {
      ...mapActions({
          signoutAction: 'auth/signout'
      }),
      signout () {
          this.signoutAction().then(() => {
              this.$router.replace({
                  name: 'home'
              })
          }).catch(() => {
            this.$router.replace({
              name: 'home'
            })
          })
      }
  }
};
</script>

<style scoped>
ul {
  list-style-type: none;
  margin: 0;
  padding: 0;
  overflow: hidden;
  background-color: #333333;
}

li {
  float: left;
}

li.right {
  float: right;
  display: block;
  color: white;
  text-align: center;
  padding: 16px;
  text-decoration: none;
}

li a {
  display: block;
  color: white;
  text-align: center;
  padding: 16px;
  text-decoration: none;
}

li a:hover {
  background-color: #111111;
}
</style>