<template>
  <div class="home">
    
<div class="con">
      <header class="head-form">
        <h2>CA Administrator</h2>
      </header>
      <br>
      <div class="field-set">
        <div>
            <label for="issued">Issued certificates</label>
            <p id="issued"> {{ ca_info.issued }} </p>
        </div>
        <div>
            <label for="revoked">Revoked certificates</label>
            <p id="revoked"> {{ ca_info.revoked }} </p>
        </div>
        <div>
            <label for="serial">Current serial number</label>
            <p id="serial"> {{ ca_info.serial }} </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { mapGetters, mapActions } from "vuex";

export default {
  name: 'Admin',
  components: {
    //
  },
   computed: {
    ...mapGetters({
      ca_info: "auth/ca_info",
    }),
  },
  methods: {
    ...mapActions({
      update_ca_info: "auth/update_ca_info",
    })
  },
  created: function() {
    let self = this;
		setInterval(function() {
      self.update_ca_info();
    }, 3000);
	},
}
</script>

<style scoped>
* {
  padding: 0;
  margin: 0;
  box-sizing: border-box;
}

p {
  display: block;
  background: rgb(250, 250, 250);
  color: #333;
  padding: 14.5px 0px 15px 9px;
  border-radius: 5px 0px 0px 5px;
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

.home {
  width: 450px;
  min-height: 500px;
  height: auto;
  border-radius: 5px;
  margin: 2% auto;
  box-shadow: 0 9px 50px hsla(20, 67%, 75%, 0.31);
  padding: 2%;
  background-image: linear-gradient(-225deg, #e3fdf5 50%, #ffe6fa 50%);
}

.home .con {
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
