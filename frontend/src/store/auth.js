import axios from "axios";
const https = require("https");

export default {
  namespaced: true,
  state: {
    token: null,
    user: null,
    cert: null,
    cert_id: null,
    ca_info: null,
    name: null,
    password: null,
  },
  mutations: {
    SET_TOKEN(state, token) {
      state.token = token;
    },
    SET_PASSWORD(state, pass) {
      state.password = pass;
    },
    SET_NAME(state, name) {
      state.name = name;
    },
    SET_USER(state, user) {
      state.user = {
        firstname: user.first_name,
        lastname: user.last_name,
        email: user.email,
      };
    },
    SET_CERT_ID(state, cert_id) {
      state.cert_id = cert_id;
    },
    SET_CERT(state, cert) {
      state.cert = cert;
    },
    SET_CA_INFO(state, ca_info) {
      state.ca_info = ca_info;
    },
  },
  getters: {
    authenticated(state) {
      return state.token && state.user;
    },

    admin(state) {
      return state.token && state.user && state.user.admin == "1";
    },

    ca_info(state) {
      return state.ca_info;
    },

    user(state) {
      return state.user;
    },

    cert_id(state) {
      return state.cert_id;
    },

    cert(state) {
      return state.cert;
    },
  },
  actions: {
    async refresh_token({ dispatch}, token) {
      let head = {};
      if (document.cookie != "") {
        head = {
          headers: {
            "X-CSRFToken": decodeURIComponent(
              document.cookie
                .split(";")[0]
                .trim()
                .substring("csfrtoken".length + 1)
            ),
          },
        };
      }
      let response = await axios.post(
        "/refresh_token/",
        { token: token },
        head
      );

      if (response.data.refresh_token) {
        let head = {};
        if (document.cookie != "") {
          head = {
            headers: {
              "X-CSRFToken": decodeURIComponent(
                document.cookie
                  .split(";")[0]
                  .trim()
                  .substring("csfrtoken".length + 1)
              ),
            },
          };
        }
        let response = await axios.post(
          "/new_token/",
          { refresh_token: response.data.refresh_token },
          head
        );

        if (response.data.token) {
          return dispatch("attempt", response.data.token);
        }
      }
    },

    async login({ dispatch, commit }, credentials) {
      try {
        let head = {};
        if (document.cookie != "") {
          head = {
            headers: {
              "X-CSRFToken": decodeURIComponent(
                document.cookie
                  .split(";")[0]
                  .trim()
                  .substring("csfrtoken".length + 1)
              ),
            },
          };
        }
        let response = await axios.post("/login/", credentials, head);

        if (response.status && response.status != 200) {
          return;
        } else if (response.data) {
          commit("SET_PASSWORD", credentials.password);
          return dispatch("attempt", response.data.access_token);
        }
      } catch (e) {
        console.log("Login error: ", e);
        return;
      }
    },

    async login_cert({ dispatch }, credentials) {
      console.log("cert", credentials);

      const httpsAgent = new https.Agent({
        cert: "cert",
        key: "key",
        ca: "ca",
        passphrase: "passphrase",
      });

      console.log(httpsAgent);

      let response = await axios.post("/login_cert/", { httpsAgent });

      console.log(response);

      if (response.data) {
        return dispatch("attempt", response.data.access_token);
      }
    },

    async update_ca_info({ commit, getters }) {
      if (getters.admin && getters.authenticated) {
        let head = {};
        if (document.cookie != "") {
          head = {
            headers: {
              "X-CSRFToken": decodeURIComponent(
                document.cookie
                  .split(";")[0]
                  .trim()
                  .substring("csfrtoken".length + 1)
              ),
            },
          };
        }
        let response = await axios.get("/status_cert/", head);
        //let response = { data: { issued: 11, revoked: 2, serial: 20101010 } }

        commit("SET_CA_INFO", response.data);
      }
    },

    async attempt({ commit, state }, token) {
      if (token) {
        commit("SET_TOKEN", token);
      }
      if (!state.token) {
        return;
      }

      try {
        let head = {};
        if (document.cookie != "") {
          head = {
            headers: {
              "X-CSRFToken": decodeURIComponent(
                document.cookie
                  .split(";")[0]
                  .trim()
                  .substring("csfrtoken".length + 1)
              ),
            },
          };
        }
        let response = await axios.get("/userinfo/", head);

        commit("SET_USER", response.data);

        if (response.data.admin) {
          let head = {};
          if (document.cookie != "") {
            head = {
              headers: {
                "X-CSRFToken": decodeURIComponent(
                  document.cookie
                    .split(";")[0]
                    .trim()
                    .substring("csfrtoken".length + 1)
                ),
              },
            };
          }
          let response = await axios.get("/status_cert/", head);

          commit("SET_CA_INFO", response.data);
        }
      } catch (e) {
        commit("SET_TOKEN", null);
        commit("SET_USER", null);
      }
    },

    async edit({ commit, dispatch, state }, credentials) {
      try {
        let head = {};
        if (document.cookie != "") {
          head = {
            headers: {
              "X-CSRFToken": decodeURIComponent(
                document.cookie
                  .split(";")[0]
                  .trim()
                  .substring("csfrtoken".length + 1)
              ),
            },
          };
        }
        let response = await axios.post(
          "/update/",
          {
            last_name: credentials.lastname,
            first_name: credentials.firstname,
            email: credentials.email,
            token: state.token,
          },
          head
        );

        if (response.status && response.status == 200) {
          commit("SET_NAME", credentials.firstname);
          return dispatch("attempt");
        } else {
          return;
        }
      } catch (e) {
        if(e.response.data.description && e.response.data.description.includes('token is expired')) {
          return dispatch("refresh_token", state.token).then(() => {
            return dispatch("edit", credentials)
          });
        } else {
          return;
        }
      }
    },

    async generate_cert({ dispatch, state }) {
      console.log("generate_cert");
      let head = {};
      if (document.cookie != "") {
        head = {
          headers: {
            "X-CSRFToken": decodeURIComponent(
              document.cookie
                .split(";")[0]
                .trim()
                .substring("csfrtoken".length + 1)
            ),
          },
        };
      }
      let response = await axios.post(
        "/generate_cert/",
        { token: state.token },
        head
      );

      console.log(response.status, response)

      if (response.status && response.status == 200) {
        console.log(response.data);
        return dispatch("generate_attempt", response.data);
      }
    },

    async generate_attempt({ commit , state }, cert) {
      //console.log("generate_attempt", cert.uid);

      if (cert) {
        commit("SET_CERT_ID", cert);
      }

      if (!state.cert_id) {
        return;
      }

      try {
        let head = {};
        if (document.cookie != "") {
          head = {
            headers: {
              "X-CSRFToken": decodeURIComponent(
                document.cookie
                  .split(";")[0]
                  .trim()
                  .substring("csfrtoken".length + 1)
              ),
              'Content-Type': 'multipart/form-data',
            },
          };
        }

        let formData = new FormData();
        formData.append('certificate', cert.archive);
        formData.append('token', state.token);
        let response = await axios.post("/verify_cert/", formData, head);

        commit("SET_CERT", response.data.certif);
      } catch (e) {
        commit("SET_CERT", null);
        commit("SET_CERT_ID", null);
      }
    },

    async download_cert({ commit }, object_id) {
      console.log("download_cert");

      if (object_id) {
        commit("SET_CERT_ID", object_id);
      }

      try {
        let head = {};
        if (document.cookie != "") {
          head = {
            headers: {
              "X-CSRFToken": decodeURIComponent(
                document.cookie
                  .split(";")[0]
                  .trim()
                  .substring("csfrtoken".length + 1)
              ),
            },
          };
        }
        let response = await axios
          .post("/download_cert/", object_id, head)
          .then((response) => {
            let data = JSON.stringify(response.data);
            const blob = new Blob([data], { type: "application/json" });
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.download = "cert.pkcs";
            link.click();
            URL.revokeObjectURL(link.href);
          })
          .catch(console.error);
        // delete
        /*let response = { data: { certif: "certificate"} };
        let data = JSON.stringify(response.data)
        const blob = new Blob([data], { type: 'application/json' })
        const link = document.createElement('a')
        link.href = URL.createObjectURL(blob)
        link.download = "cert.pkcs"
        link.click()
        URL.revokeObjectURL(link.href)*/

        commit("SET_CERT", response.data.certif);
      } catch (e) {
        commit("SET_CERT", null);
        commit("SET_CERT_ID", null);
      }
    },

    async revoke_cert({ commit }) {
      console.log("revoke_cert");
      let head = {};
      if (document.cookie != "") {
        head = {
          headers: {
            "X-CSRFToken": decodeURIComponent(
              document.cookie
                .split(";")[0]
                .trim()
                .substring("csfrtoken".length + 1)
            ),
          },
        };
      }
      let response = await axios.post("/revoke_cert/", {}, head);
      // let response = { status: 200 };

      if (response.status && response.status == 200) {
        commit("SET_CERT_ID", null);
        commit("SET_CERT", null);
      }
    },

    signout({ commit, state }) {
      try {
        let head = {};
        if (document.cookie != "") {
          head = {
            headers: {
              "X-CSRFToken": decodeURIComponent(
                document.cookie
                  .split(";")[0]
                  .trim()
                  .substring("csfrtoken".length + 1)
              ),
            },
          };
        }
        return axios.post("/logout/", { token: state.token }, head).then(() => {
          commit("SET_TOKEN", null);
          commit("SET_NAME", null);
          commit("SET_USER", null);
          commit("SET_CERT_ID", null);
          commit("SET_CERT", null);
          commit("SET_CA_INFO", null);
        });
      } catch (e) {
        console.log(e);

        commit("SET_TOKEN", null);
        commit("SET_NAME", null);
        commit("SET_USER", null);
        commit("SET_CERT_ID", null);
        commit("SET_CERT", null);
        commit("SET_CA_INFO", null);
      }
    },
  },
};
