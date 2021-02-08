<template>
  <form @submit.prevent="">
    <div class="con">
      <header class="head-form">
        <h2>Log In</h2>
        <p class="fail" :style="{visibility: fail ? 'visible' : 'hidden'}">Incorrect credentials try again</p>
      </header>
      <br>
      <div class="field-set">
        <div>
            <label for="email">Email</label>
            <input class="form-input" type="email" name="email" id="email" v-model="auth.email" />
        </div>
        <div>
            <label for="password">Password</label>
            <input
            type="password"
            name="password"
            id="password"
            class="form-input"
            v-model="auth.password"
            />
        </div>
        <div>
            <button class="log.in" type="submit" @click.prevent="submit">Login</button>
        </div>
        <div>
            <button class="log.in" type="submit" @click.prevent="submit_cert">Login with cert</button>
        </div>
      </div>
    </div>
  </form>
</template>

<script>
import { mapActions } from "vuex";
export default {
  name: "login",
  components: {
    //
  },
  methods: {
    ...mapActions({
      login: "auth/login",
      login_cert: "auth/login_cert",
    }),
    submit() {
        this.fail = false;

        let credentials = {
            username: this.auth.email,
            password: this.auth.password
        }
      this.login(credentials)
        .then(() => {
          this.$router.replace({
            name: "dashboard",
          });
        })
        .catch(() => {
          this.fail = true;
        });
    },
    submit_cert() {
      this.fail = false;
      
      let credentials = {
        username: this.auth.email
      }
      this.login_cert(credentials).then(() => {
          this.$router.replace({
            name: "dashboard",
          });
        })
        .catch(() => {
          this.fail = true;
        });

    }
  },
  data() {
    return {
      auth: {
        email: "",
        password: "",
      },
      fail: false,
    };
  },
};
</script>

<style scoped>
* {
  padding: 0;
  margin: 0;
  box-sizing: border-box;
}

form {
  width: 450px;
  min-height: 500px;
  height: auto;
  border-radius: 5px;
  margin: 2% auto;
  box-shadow: 0 9px 50px hsla(20, 67%, 75%, 0.31);
  padding: 2%;
  background-image: linear-gradient(-225deg, #e3fdf5 50%, #ffe6fa 50%);
}

form .con {
  display: -webkit-flex;
  display: flex;

  -webkit-justify-content: space-around;
  justify-content: space-around;

  -webkit-flex-wrap: wrap;
  flex-wrap: wrap;

  margin: 0 auto;
}

header {
  margin: 2% auto 10% auto;
  text-align: center;
}

header h2 {
  font-size: 250%;
  font-family: "Playfair Display", serif;
  color: #3e403f;
}

.fail {
    color: red;
}

header p {
  letter-spacing: 0.05em;
}

.input-item {
  background: #fff;
  color: #333;
  padding: 14.5px 0px 15px 9px;
  border-radius: 5px 0px 0px 5px;
}

label {
    display: block;
    margin-top: 10px;
} 

#eye {
  background: #fff;
  color: #333;

  margin: 5.9px 0 0 0;
  margin-left: -20px;
  padding: 15px 9px 19px 0px;
  border-radius: 0px 5px 5px 0px;

  float: right;
  position: relative;
  right: 1%;
  top: -0.2%;
  z-index: 5;

  cursor: pointer;
}

.field-set {

}

input[class="form-input"] {
  width: 280px;
  height: 50px;

  margin-top: 2%;
  padding: 15px;

  font-size: 16px;
  font-family: "Abel", sans-serif;
  color: #5e6472;

  outline: none;
  border: none;

  border-radius: 0px 5px 5px 0px;
  transition: 0.2s linear;
}
input[id="txt-input"] {
  width: 250px;
}

input:focus {
  transform: translateX(-2px);
  border-radius: 5px;
}

button {
  display: inline-block;
  color: #252537;

  width: 280px;
  height: 50px;

  padding: 0 20px;
  background: #fff;
  border-radius: 5px;

  outline: none;
  border: none;

  cursor: pointer;
  text-align: center;
  transition: all 0.2s linear;

  margin: 7% auto;
  letter-spacing: 0.05em;
}

.submits {
  width: 48%;
  display: inline-block;
  float: left;
  margin-left: 2%;
}

.frgt-pass {
  background: transparent;
}

.sign-up {
  background: #b8f2e6;
}

button:hover {
  transform: translatey(3px);
  box-shadow: none;
}

button:hover {
  animation: ani9 0.4s ease-in-out infinite alternate;
}
@keyframes ani9 {
  0% {
    transform: translateY(3px);
  }
  100% {
    transform: translateY(5px);
  }
}
</style>
