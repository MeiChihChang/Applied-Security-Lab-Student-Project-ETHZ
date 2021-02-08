<template>
  <div class="dashboard">
    {{ cert_id }} {{ cert }}
    <form @submit.prevent="">
      <div class="con">
        <header class="head-form">
          <h2>Dashboard</h2>
          <p class="fail" :style="{ display: fail_edit ? 'block' : 'none' }">
            Edit failed try again later
          </p>
          <p
            class="fail"
            :style="{ display: fail_generate ? 'block' : 'none' }"
          >
            CERT generation failed try again later
          </p>
          <p
            class="fail"
            :style="{ display: fail_download ? 'block' : 'none' }"
          >
            CERT download failed try again later or generate the CERT first
          </p>
          <p class="correct" :style="{ display: correct ? 'block' : 'none' }">
            Operation executed correctly
          </p>
        </header>
        <br />
        <div class="field-set">
          <div>
            <label for="firstname">First Name</label>
            <input
              class="form-input"
              type="text"
              name="firstname"
              id="firstname"
              v-model="userinfo.firstname"
            />
          </div>
          <div>
            <label for="lastname">Last Name</label>
            <input
              class="form-input"
              type="text"
              name="lastname"
              id="lastname"
              v-model="userinfo.lastname"
            />
          </div>
          <div>
            <label for="email">Email</label>
            <input
              class="form-input"
              type="email"
              name="email"
              id="email"
              v-model="userinfo.email"
            />
          </div>
          <div class="buttons">
            <button class="log.in" type="submit" @click.prevent="edit_info">
              Edit
            </button>
            <button class="log.in" type="submit" @click.prevent="generate_cert">
              Generate CERT
            </button>
          </div>
          <div class="buttons">
            <button class="log.in" type="submit" @click.prevent="download_cert">
              Download CERT
            </button>
            <button class="log.in" type="submit" @click.prevent="revoke_cert">
              Revoke CERT
            </button>
          </div>
        </div>
      </div>
    </form>
  </div>
</template>

<script>
import { mapGetters, mapActions } from "vuex";

export default {
  name: "dashboard",
  components: {
    //
  },
  computed: {
    ...mapGetters({
      authenticated: "auth/authenticated",
      computedinfo: "auth/user",
      cert_id: "auth/cert_id",
      cert: "auth/cert",
    }),
  },
  created() {
    this.userinfo.lastname = this.computedinfo.lastname;
    this.userinfo.firstname = this.computedinfo.firstname;
    this.userinfo.email = this.computedinfo.email;
  },
  methods: {
    ...mapActions({
      edit: "auth/edit",
      generate: "auth/generate_cert",
      download: "auth/download_cert",
      revoke: "auth/revoke_cert",
    }),
    edit_info() {
      let credentials = {
        firstname: this.userinfo.firstname,
        lastname: this.userinfo.lastname,
        email: this.userinfo.email,
      };
      this.edit(credentials)
        .then(() => {
          this.correct = true;
          setTimeout(() => (this.correct = false), 5000);
          this.userinfo.lastname = this.computedinfo.lastname;
          this.userinfo.firstname = this.computedinfo.firstname;
          this.userinfo.email = this.computedinfo.email;
        })
        .catch(() => {
          this.fail_edit = true;
          setTimeout(() => (this.fail_edit = false), 5000);
        });
    },
    generate_cert() {
      this.generate()
        .then(() => {
          this.correct = true;
          setTimeout(() => (this.correct = false), 5000);
          console.log("OK");
        })
        .catch(() => {
          this.fail_generate = true;
          setTimeout(() => (this.fail_generate = false), 5000);
        });
    },
    download_cert() {
      if (this.cert_id) {
        this.download(this.cert_id)
          .then(() => {
            this.correct = true;
            setTimeout(() => (this.correct = false), 5000);
            //download the cert
          })
          .catch(() => {
            this.fail_download = true;
            setTimeout(() => (this.fail_download = false), 5000);
          });
      } else {
        this.fail_download = true;
        setTimeout(() => (this.fail_download = false), 5000);
      }
    },
    revoke_cert() {
      this.revoke().then(() => {
        this.correct = true;
          setTimeout(() => (this.correct = false), 5000);
          console.log("OK");
      }).catch(() => {
          this.fail_generate = true;
          setTimeout(() => (this.fail_generate = false), 5000);
        });
    }
  },
  data() {
    return {
      userinfo: {},
      fail_edit: false,
      fail_download: false,
      fail_generate: false,
      correct: false,
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

.buttons {
  display: flex;
  flex-direction: column;
}

form {
  width: 650px;
  min-height: 500px;
  height: auto;
  border-radius: 5px;
  margin: 2% auto;
  box-shadow: 0 9px 50px hsla(20, 67%, 75%, 0.31);
  padding: 2%;
  background-image: linear-gradient(-225deg, #e3fdf5 50%, #b5eedd 50%);
}

form .con {
  display: -webkit-flex;
  display: flex;

  -webkit-justify-content: space-around;
  justify-content: space-around;

  -webkit-flex-wrap: wrap;
  flex-wrap: wrap;

  flex-direction: column;

  margin: 0 auto;
}

header {
  margin: 1% auto 1% auto;
  text-align: center;
}

header h2 {
  font-size: 250%;
  font-family: "Playfair Display", serif;
  color: #3e403f;
}

.correct {
  color: greenyellow;
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
  display: block;
  margin: 0 auto;
  padding-left: 5%;
}

input[class="form-input"] {
  width: 280px;
  height: 50px;

  margin: 0 auto;
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

  margin-top: 8%;
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
