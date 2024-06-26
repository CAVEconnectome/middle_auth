const AUTH_URL = "../api/v1";

const permissionNames = ["none", "view", "edit", "admin_view"];

const datasetDataApp = {
  data: () => ({
    loading: true,
    newEntry: false,
    dataset: null,
    errors: [],
    groups: [],
    admins: [],
    permissions: [],
    allGroups: [],
    availableGroups: [],
    toses: [],
    selectedGroup: "",
    selectedPermission: "",
    availablePermissions: [],
    chosen: "",
  }),
  async beforeRouteUpdate(to, from, next) {
    await this.load(to.params.id);
    next();
  },
  mounted: async function () {
    await this.load(this.$route.params.id);
  },
  methods: {
    async load(param_id) {
      this.loading = true;

      this.toses = await authFetch(`${AUTH_URL}/tos`);

      this.newEntry = param_id === "create";

      if (this.newEntry) {
        this.loading = false;

        this.dataset = {
          name: "",
          tos_id: null,
        };

        return;
      }

      const id = Number.parseInt(param_id);

      this.availablePermissions = await authFetch(`${AUTH_URL}/permission`);

      this.dataset = await authFetch(`${AUTH_URL}/dataset/${id}`);
      this.permissions = await authFetch(`${AUTH_URL}/dataset/${id}/group`);
      this.allGroups = await authFetch(`${AUTH_URL}/group`);
      this.admins = await authFetch(`${AUTH_URL}/dataset/${id}/admin`);
      await this.updateAvailableGroups();

      this.loading = false;
    },
    async updateAvailableGroups() {
      this.availableGroups = this.allGroups;
      /*.filter((group) => {
				return !this.groups.map((g) => g.id).includes(group.id);
			});*/
    },
    async addGroupDataset() {
      await authFetch(`${AUTH_URL}/dataset/${this.dataset.id}/group`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          group_id: this.selectedGroup,
          permission_ids: [Number.parseInt(this.selectedPermission)],
        }),
      });

      this.permissions = await authFetch(`${AUTH_URL}/dataset/${id}/group`);
      await this.updateAvailableGroups();
    },
    async removeGroup(group) {
      await authFetch(
        `${AUTH_URL}/dataset/${this.dataset.id}/group/${group.id}/permission/${group.permission_id}`,
        {
          method: "DELETE",
        }
      );

      this.permissions = await authFetch(`${AUTH_URL}/dataset/${id}/group`);

      await this.updateAvailableGroups();
    },
    async save() {
      this.errors = [];

      if (!this.dataset.name) {
        this.errors.push(["name", "missing"]);
      }

      if (!this.errors.length) {
        await authFetch(`${AUTH_URL}/dataset`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            name: this.dataset.name,
            tos_id: this.dataset.tos_id,
          }),
        })
          .then((res) => {
            router.push({ name: "datasetData", params: { id: res.id } });
          })
          .catch((res) => {
            alert(res);
          });
      }
    },
    async update() {
      await authFetch(`${AUTH_URL}/dataset/${this.dataset.id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: this.dataset.name,
          tos_id: this.dataset.tos_id,
        }),
      });

      await this.load(this.$route.params.id);
    },
    async simpleSuggestionList(email) {
      const users = await authFetch(`${AUTH_URL}/user?email=${email}`);

      return users.map((user) => {
        return {
          id: user.id,
          name: `${user.name} (${user.email})`,
        };
      });
    },
    async addAdmin(user) {
      if (!user) {
        return;
      }

      await authFetch(`${AUTH_URL}/dataset/${this.dataset.id}/admin`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          dataset_id: this.dataset.id,
          user_id: user.id,
        }),
      });

      this.admins = await authFetch(
        `${AUTH_URL}/dataset/${this.dataset.id}/admin`
      );
    },
    async removeAdmin(admin) {
      await authFetch(
        `${AUTH_URL}/dataset/${this.dataset.id}/admin/${admin.id}`,
        {
          method: "DELETE",
        }
      );

      this.admins = await authFetch(
        `${AUTH_URL}/dataset/${this.dataset.id}/admin`
      );
    },
  },
  template: `
	<div id="datasetData">
		<div class="title" v-if="newEntry">Create Dataset</div>
		<div class="title" v-else>Edit Dataset</div>
		<template v-if="loading">
			<div>Loading...</div>
		</template>
		<template v-else>
			<input v-model="dataset.name" placeholder="Name" required>

			<label>Terms of Service</label>
			<select v-model="dataset.tos_id">
				<option :value="null">None</option>
				<option v-for="tos in toses" v-bind:value="tos.id">{{ tos.name }}</option>
			</select>

			<template v-if="!newEntry">
				<div class="listContainer">
					<div class="header"><span>Groups</span></div>
					<div class="permissions list threeColumn">
						<div v-for="group in permissions">
							<router-link :to="{ name: 'groupData', params: { id: group.id }}">
								{{ group.name }}
							</router-link>
							<div>
								{{ group.permission }}
							</div>
							<div class="deleteRow" @click="removeGroup(group)"></div>
						</div>
					</div>
				</div>

				<div>
					<select v-model="selectedGroup">
						<option disabled="disabled" value="">Select Group</option>
						<option v-for="group in availableGroups" v-bind:value="group.id">{{ group.name }}</option>
					</select>
					<select v-model="selectedPermission">
						<option disabled="disabled" value="">Select Permission</option>
						<option v-for="permission in availablePermissions" :value="permission.id">{{permission.name}}</option>
					</select>
					<button @click="addGroupDataset">Add Group</button>
				</div>

				<div v-if="!loading" class="listContainer">
					<div class="header"><span>Admins</span></div>
					<div class="admins list twoColumn">
						<div v-for="admin in admins">
							<router-link :to="{ name: 'userData', params: { id: admin.id }}">
								{{ admin.name }}
							</router-link>
							<div v-if="$parent.loggedInUser.admin" class="deleteRow" @click="removeAdmin(admin)"></div>
							<div v-else></div>
						</div>
					</div>
				</div>

				<vue-simple-suggest
					placeholder="Add Admin (by email)"
					v-model="chosen"
					v-on:suggestion-click="addAdmin"
					:list="simpleSuggestionList"
					:filter-by-query="false"
					display-attribute="name"
					value-attribute="id">
				</vue-simple-suggest>
			</template>
			<button @click="save" v-if="newEntry">Create</button>
			<button @click="update" v-else>Save</button>
		</template>
	</div>
	`,
};

const groupDataApp = {
  data: () => ({
    loading: true,
    newEntry: false,
    group: null,
    users: [],
    serviceAccounts: [],
    admins: [],
    nonAdmins: [],
    permissions: [],
    availableDatasets: [],
    allDatasets: [],
    selectedUser: "",
    selectedDataset: "",
    selectedPermission: "",
    availablePermissions: [],
    chosen: "",
  }),
  async beforeRouteUpdate(to, from, next) {
    await this.load(to.params.id);
    next();
  },
  mounted: async function () {
    await this.load(this.$route.params.id);
  },
  methods: {
    async load(param_id) {
      this.loading = true;
      this.newEntry = param_id === "create";

      if (param_id === "create") {
        this.loading = false;

        this.group = {
          name: "",
        };

        return;
      }

      const id = Number.parseInt(param_id);

      let [
        group,
        users,
        serviceAccounts,
        permissions,
        availableDatasets,
        availablePermissions,
      ] = await authFetch([
        `${AUTH_URL}/group/${id}`,
        `${AUTH_URL}/group/${id}/user`,
        `${AUTH_URL}/group/${id}/service_account`,
        `${AUTH_URL}/group/${id}/dataset`,
        `${AUTH_URL}/dataset`,
        `${AUTH_URL}/permission`,
      ]);

      this.group = group;

      this.users = users;
      this.serviceAccounts = serviceAccounts;
      this.admins = await authFetch(`${AUTH_URL}/group/${id}/admin`);
      this.updateNonAdmins();
      this.permissions = permissions;

      this.allDatasets = availableDatasets;
      this.updateAvailableDatasets();

      this.availablePermissions = availablePermissions;

      this.loading = false;
    },
    async simpleSuggestionList(email) {
      const users = await authFetch(`${AUTH_URL}/user?email=${email}`);

      return users
        .map((user) => {
          user.member = this.users.map((other) => other.id).includes(user.id);

          return user;
        })
        .sort((a, b) => {
          return a.member - b.member;
        });
    },
    async addUser(user) {
      if (!user) {
        return;
      }

      await authFetch(`${AUTH_URL}/group/${this.group.id}/user`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          user_id: user.id,
        }),
      });

      this.users = await authFetch(`${AUTH_URL}/group/${this.group.id}/user`);
      this.serviceAccounts = await authFetch(
        `${AUTH_URL}/group/${this.group.id}/service_account`
      );
      this.updateNonAdmins();
    },
    async removeUser(userId) {
      await authFetch(`${AUTH_URL}/group/${this.group.id}/user/${userId}`, {
        method: "DELETE",
      });

      this.users = await authFetch(`${AUTH_URL}/group/${this.group.id}/user`);
      this.serviceAccounts = await authFetch(
        `${AUTH_URL}/group/${this.group.id}/service_account`
      );
      this.admins = await authFetch(`${AUTH_URL}/group/${this.group.id}/admin`);
      this.updateNonAdmins();
    },
    async makeAdmin() {
      this.setAdmin(parseInt(this.selectedUser), true);
    },
    async setAdmin(userId, admin) {
      await authFetch(`${AUTH_URL}/group/${this.group.id}/user/${userId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          admin: admin,
        }),
      });

      this.users = await authFetch(`${AUTH_URL}/group/${this.group.id}/user`);
      this.admins = await authFetch(`${AUTH_URL}/group/${this.group.id}/admin`);
      this.updateNonAdmins();
    },
    async addGroupDataset() {
      await authFetch(`${AUTH_URL}/dataset/${this.selectedDataset}/group`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          group_id: this.group.id,
          permission_ids: [Number.parseInt(this.selectedPermission)],
        }),
      });

      this.permissions = await authFetch(
        `${AUTH_URL}/group/${this.group.id}/dataset`
      );
      this.updateAvailableDatasets();
    },
    updateAvailableDatasets() {
      this.availableDatasets = this.allDatasets;
      /*.filter((dataset) => {
				return !this.datasets.map((d) => d.id).includes(dataset.id);
			});*/
    },
    updateNonAdmins() {
      this.nonAdmins = this.users.filter((user) => {
        return !this.admins.map((u) => u.id).includes(user.id);
      });
    },
    async removeDatasetPermission(permission) {
      await authFetch(
        `${AUTH_URL}/dataset/${permission.id}/group/${this.group.id}/permission/${permission.permission_id}`,
        {
          method: "DELETE",
        }
      );

      this.permissions = await authFetch(
        `${AUTH_URL}/group/${this.group.id}/dataset`
      );
      this.updateAvailableDatasets();
    },
    async save() {
      this.errors = [];

      if (this.newEntry) {
        console.log("save new entry!");

        if (!this.group.name) {
          this.errors.push(["name", "missing"]);
        }

        if (!this.errors.length) {
          authFetch(`${AUTH_URL}/group`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              name: this.group.name,
            }),
          })
            .then((res) => {
              console.log("updated entry!");
              router.push("./");
            })
            .catch((res) => {
              alert(res);
            });
        }
      } else {
        console.log("update entry!");
      }
    },
  },
  template: `
	<div id="groupData">
		<template v-if="loading">
			<div>Loading...</div>
		</template>
		<template v-else-if="newEntry">
			<div class="title">Create Group</div>

			<input v-model="group.name" placeholder="Name" required>

			<button @click="save">Create</button>
		</template>
		<template v-else>
			<div class="title">Edit Group</div>
			<div class="name">{{ group.name }}</div>

			<div class="listContainer">
				<div class="header">Admins</div>
				<div class="admins list twoColumn">
					<div v-for="user in admins">
						<div>
							<router-link :to="{ name: 'userData', params: { id: user.id }}">
								{{ user.name }}
							</router-link>
						</div>
						<div v-if="$parent.loggedInUser.admin" class="deleteRow" @click="setAdmin(user.id, false)"></div>
						<div v-else></div>
					</div>
				</div>
			</div>

			<div v-if="$parent.loggedInUser.admin">
				<select v-model="selectedUser">
					<option disabled="disabled" value="">Select User</option>
					<option v-for="user in nonAdmins" v-bind:value="user.id">{{ user.name }}</option>
				</select>
				<button @click="makeAdmin">Make Admin</button>
			</div>

			<div class="listContainer">
				<div class="header"><span>Datasets</span></div>
				<div class="datasets list threeColumn">
					<div v-for="permission in permissions">
						<router-link :to="{ name: 'datasetData', params: { id: permission.id }}">
							{{ permission.name }}
						</router-link>
						<div class="datasetPermission">{{ permission.permission }}</div>
						<div class="deleteRow" @click="removeDatasetPermission(permission)"></div>
					</div>
				</div>
			</div>

			<div>
				<select v-model="selectedDataset">
					<option disabled="disabled" value="">Select Dataset</option>
					<option v-for="dataset in availableDatasets" v-bind:value="dataset.id">{{ dataset.name }}</option>
				</select>
				<select v-model="selectedPermission">
					<option disabled="disabled" value="">Select Permission</option>
					<option v-for="permission in availablePermissions" :value="permission.id">{{permission.name}}</option>
				</select>
				<button @click="addGroupDataset">Add Dataset</button>
			</div>

			<div class="listContainer">
				<div class="header">Users</div>
				<div class="users list twoColumn">
					<div v-for="user in users">
						<div>
							<router-link :to="{ name: 'userData', params: { id: user.id }}">
								{{ user.name }}
							</router-link>
							<span class="is_admin" v-if="user.admin">Admin</span>
						</div>
						<div v-if="$parent.loggedInUser.admin || !user.admin" class="deleteRow" @click="removeUser(user.id)"></div>
						<div v-else></div>
					</div>
				</div>
			</div>

			<div class="listContainer">
				<div class="header">Service Accounts</div>
				<div class="users list twoColumn">
					<div v-for="user in serviceAccounts">
						<div>
							<router-link :to="{ name: 'serviceAccountData', params: { id: user.id }}">
								{{ user.name }}
							</router-link>
						</div>
						<div class="deleteRow" @click="removeUser(user.id)"></div>
					</div>
				</div>
			</div>

			<vue-simple-suggest
				placeholder="Add User (by email)"
				v-model="chosen"
				v-on:select="addUser"
				:list="simpleSuggestionList"
				:filter-by-query="false"
				display-attribute="name"
				value-attribute="id">

				<div :class="{ member: scope.suggestion.member }" class="suggestion-item-data" slot="suggestion-item" slot-scope="scope">
					<div class="text">{{ scope.suggestion.name }}</div>
					<div class="text">({{ scope.suggestion.email }})</div>
					<div class="text" v-if="scope.suggestion.member">Member</div>
				</div>

			</vue-simple-suggest>
		</template>
	</div>
	`,
};

const userDataApp = {
  data: () => ({
    loading: true,
    newEntry: false,
    user: null,
    groups: [],
    availableGroups: [],
    allGroups: [],
    selectedGroup: "",
  }),
  async beforeRouteUpdate(to, from, next) {
    await this.load(to.params.id);
    next();
  },
  mounted: async function () {
    await this.load(this.$route.params.id);
  },
  methods: {
    async load(param_id) {
      this.loading = true;
      this.newEntry = param_id === "create";

      if (param_id === "create") {
        this.loading = false;

        this.user = {
          name: "",
        };

        return;
      }

      const id = Number.parseInt(param_id);

      let [userInfo, usersGroups, groups, toses, permissions] = await authFetch(
        [
          `${AUTH_URL}/user/${id}`,
          `${AUTH_URL}/user/${id}/group`,
          `${AUTH_URL}/group`,
          `${AUTH_URL}/user/${id}/tos`,
          `${AUTH_URL}/user/${id}/permissions`,
        ]
      );

      this.user = userInfo;
      this.groups = usersGroups;
      this.allGroups = groups;
      this.toses = toses;
      this.permissions = permissions;

      this.updateAvailableGroups();

      this.loading = false;
    },
    updateAvailableGroups() {
      this.availableGroups = this.allGroups.filter((group) => {
        return !this.groups.map((g) => g.id).includes(group.id);
      });
    },
    async create() {
      const user = await authFetch(`${AUTH_URL}/user`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: this.user.name,
          email: this.user.email,
          pi: this.user.pi,
        }),
      });

      if (user) {
        router.push({ name: "userData", params: { id: user.id } });
      }
    },
    async update() {
      await authFetch(`${AUTH_URL}/user/${this.user.id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          admin: this.user.admin,
          pi: this.user.pi,
        }),
      });

      this.user = await authFetch(`${AUTH_URL}/user/${this.user.id}`);
    },
    async joinGroup() {
      await authFetch(`${AUTH_URL}/group/${this.selectedGroup}/user`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          user_id: this.user.id,
        }),
      });

      this.groups = await authFetch(`${AUTH_URL}/user/${this.user.id}/group`);
      this.updateAvailableGroups();
    },
    async leaveGroup(groupId) {
      await authFetch(`${AUTH_URL}/group/${groupId}/user/${this.user.id}`, {
        method: "DELETE",
      });

      this.groups = await authFetch(`${AUTH_URL}/user/${this.user.id}/group`);
      this.updateAvailableGroups();
    },
  },
  template: `
	<div id="userData">
	<template v-if="loading">
		<div>Loading...</div>
	</template>
	<template v-else-if="newEntry">
		<div class="title">Create User</div>
		<input v-model="user.name" placeholder="Name" required>
		<input v-model="user.email" placeholder="Email" required>
		<input v-model="user.pi" placeholder="PI/Lab Head" required>
		<button @click="create">Create</button>
	</template>
	<template v-else>
		<div class="title">Edit User</div>
		<div>
			<div class="name">{{ user.name }}</div>
			<div class="email">{{ user.email }}</div>
			<div class="pi"><input v-model="user.pi" type="text"></input></div>
			<div class="admin"><input v-model="user.admin" type="checkbox"></div>
			<button @click="update">Save</button>
		</div>

		<div class="listContainer">
			<div class="header">Groups</div>
			<div class="groups list twoColumn">
				<div v-for="group in groups">
					<router-link :to="{ name: 'groupData', params: { id: group.id }}">
						{{ group.name }}
					</router-link>
					<div class="deleteRow" @click="leaveGroup(group.id)"></div>
				</div>
			</div>
		</div>

		<div>
			<select v-model="selectedGroup">
				<option disabled="disabled" value="">Select Group</option>
				<option v-for="group in availableGroups" v-bind:value="group.id">{{ group.name }}</option>
			</select>
			<button @click="joinGroup">Join Group</button>
		</div>

		<div class="listContainer">
			<div class="header">Terms of Service</div>
			<div class="groups list twoColumn">
				<div v-for="tos in toses">
					<router-link :to="{ name: 'tosData', params: { id: tos.id }}">
						{{ tos.name }}
					</router-link>
					<div class="" @click=""></div>
				</div>
			</div>
		</div>

		<div class="listContainer">
		<div class="header">Unaccepted Terms of Service</div>
		<div class="groups list twoColumn">
			<div v-for="tos in permissions.missing_tos">
				<router-link :to="{ name: 'tosData', params: { id: tos.tos_id }}">
					{{ tos.tos_name }}
				</router-link>
				<div class="" @click="">
					<router-link :to="{ name: 'datasetData', params: { id: tos.dataset_id }}">
						{{ tos.dataset_name }}
					</router-link>
				</div>
			</div>
		</div>
	</div>

	</template>
	</div>
	`,
};

const serviceAccountDataApp = {
  data: () => ({
    loading: true,
    newEntry: false,
    serviceAccount: null,
    groups: [],
    availableGroups: [],
    allGroups: [],
    selectedGroup: "",
    token: null,
  }),
  async beforeRouteUpdate(to, from, next) {
    await this.load(to.params.id);
    next();
  },
  mounted: async function () {
    await this.load(this.$route.params.id);
  },
  methods: {
    async load(param_id) {
      this.loading = true;
      this.newEntry = param_id === "create";

      if (param_id === "create") {
        this.loading = false;

        this.serviceAccount = {
          name: "",
        };

        return;
      }

      const id = Number.parseInt(param_id);

      let [serviceAccountInfo, serviceAccountGroups, groups] = await authFetch([
        `${AUTH_URL}/service_account/${id}`,
        `${AUTH_URL}/service_account/${id}/group`,
        `${AUTH_URL}/group`,
      ]);

      this.serviceAccount = serviceAccountInfo;
      this.groups = serviceAccountGroups;
      this.allGroups = groups;

      this.updateAvailableGroups();

      this.loading = false;
    },
    updateAvailableGroups() {
      this.availableGroups = this.allGroups.filter((group) => {
        return !this.groups.map((g) => g.id).includes(group.id);
      });
    },
    async create() {
      const serviceAccount = await authFetch(`${AUTH_URL}/service_account`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: this.serviceAccount.name,
        }),
      });

      router.push({
        name: "serviceAccountData",
        params: { id: serviceAccount.id },
      });

      if (serviceAccount) {
        router.push({
          name: "serviceAccountData",
          params: { id: serviceAccount.id },
        });
      }
    },
    async update() {
      await authFetch(`${AUTH_URL}/service_account/${this.serviceAccount.id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          read_only: this.serviceAccount.read_only,
        }),
      });

      this.serviceAccount = await authFetch(
        `${AUTH_URL}/service_account/${this.serviceAccount.id}`
      );
    },
    async deleteSA() {
      // cant use delete because it conflicts with javascript keyword
      await authFetch(`${AUTH_URL}/service_account/${this.serviceAccount.id}`, {
        method: "DELETE",
      });

      router.push({ name: "serviceAccountList" });
    },
    async getToken() {
      this.token = await authFetch(
        `${AUTH_URL}/service_account/${this.serviceAccount.id}/token`,
        {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    },
    async joinGroup() {
      await authFetch(
        `${AUTH_URL}/group/${this.selectedGroup}/service_account`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            sa_id: this.serviceAccount.id,
          }),
        }
      );

      this.groups = await authFetch(
        `${AUTH_URL}/service_account/${this.serviceAccount.id}/group`
      );
      this.updateAvailableGroups();
    },
    async leaveGroup(groupId) {
      await authFetch(
        `${AUTH_URL}/group/${groupId}/service_account/${this.serviceAccount.id}`,
        {
          method: "DELETE",
        }
      );

      this.groups = await authFetch(
        `${AUTH_URL}/service_account/${this.serviceAccount.id}/group`
      );
      this.updateAvailableGroups();
    },
  },
  template: `
	<div id="serviceAccountData">
	<template v-if="loading">
		<div>Loading...</div>
	</template>
	<template v-else-if="newEntry">
		<div class="title">Create Service Account</div>
		<input v-model="serviceAccount.name" placeholder="Name" required>
		<button @click="create">Create</button>
	</template>
	<template v-else>
		<div class="title">Edit Service Account</div>
		<div>
			<div class="name">{{ serviceAccount.name }}</div>
			<div v-if="token" class="token">{{ token }}</div>
			<button v-else @click="getToken">View Token</button>
			<div class="read_only"><input v-model="serviceAccount.read_only" type="checkbox"></div>
			<button @click="update">Save</button>
		</div>

		<div class="listContainer">
			<div class="header">Groups</div>
			<div class="groups list twoColumn">
				<div v-for="group in groups">
					<router-link :to="{ name: 'groupData', params: { id: group.id }}">
						{{ group.name }}
					</router-link>
					<div class="deleteRow" @click="leaveGroup(group.id)"></div>
				</div>
			</div>
		</div>

		<div>
			<select v-model="selectedGroup">
				<option disabled="disabled" value="">Select Group</option>
				<option v-for="group in availableGroups" v-bind:value="group.id">{{ group.name }}</option>
			</select>
			<button @click="joinGroup">Join Group</button>
		</div>
		<div>
			<button @click="deleteSA">Delete Service Account</button>
		</div>
	</template>
	</div>
	`,
};

Vue.component("myText", {
  props: ["placeholder", "label", "name", "value", "required"],
  template: `
<div>
	<label v-if="label">{{label}}</label>
	<input type="text"
				 :name="name"
				 :value="value"
				 @input="$emit('input',$event.target.value)"
				 :placeholder="placeholder"
				 :required="required">
</div>`,
});

Vue.component("myTextArea", {
  props: ["placeholder", "label", "name", "value", "required"],
  template: `
<div>
	<label v-if="label">{{label}}</label>
	<textarea
				 :name="name"
				 :value="value"
				 @input="$emit('input',$event.target.value)"
				 :placeholder="placeholder"
				 :required="required"></textarea>
</div>`,
});

const dataApp = {
  data: () => ({
    loading: true,
    newEntry: false,
    type: null,
    typeName: null,
    thing: null,
    initial: null,
    properties: {},
    fields: [],
    // users: [],
    // serviceAccounts: [],
    // admins: [],
    // nonAdmins: [],
    // datasets: [],
    // availableDatasets: [],
    // allDatasets: [],
    // selectedUser: '',
    // selectedDataset: '',
    // selectedPermission: '',
    // selectedPermissions: ['none', 'view', 'edit'],
    // chosen: ''
  }),
  async beforeRouteUpdate(to, from, next) {
    await this.load(to.params.id);
    next();
  },
  mounted: async function () {
    await this.load(this.$route.params.id);
  },
  methods: {
    updateForm(fieldName, value) {
      this.$set(this.thing, fieldName, value);
      this.$emit("input", this.thing);
    },
    async load(param_id) {
      this.loading = true;
      this.newEntry = param_id === "create";

      if (param_id === "create") {
        this.loading = false;

        this.thing = this.initial; //JSON.parse(JSON.stringify(init))

        return;
      }

      const id = Number.parseInt(param_id);

      let [thing] = await authFetch([`${AUTH_URL}/${this.type}/${id}`]);

      this.thing = thing;

      this.loading = false;
    },
    async save() {
      this.errors = [];

      if (this.newEntry) {
        console.log("save new entry!");

        // if (!this.thing.name) {
        // 	this.errors.push(['name', 'missing']);
        // }

        if (!this.errors.length) {
          const res = await authFetch(`${AUTH_URL}/${this.type}`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify(this.thing),
          })
            .then((res) => {
              if (this.newEntry) {
                console.log("created entry!");
              } else {
                console.log("updated entry!");
              }

              console.log("res", res);

              router.push("./");
            })
            .catch((res) => {
              alert(res);
            });
        }
      } else {
        await authFetch(`${AUTH_URL}/${this.type}/${this.thing.id}`, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(this.thing),
        });
      }
    },
  },
  template: `
	<div class="dataAppContainer">
		<template v-if="loading">
			<div>Loading...</div>
		</template>
		<template v-else="newEntry">
			<div v-if="newEntry" class="title">Create {{ typeName }}</div>
			<div v-else class="title">Edit {{ typeName }}</div>

			<component v-for="(field, index) in fields"
				:key="index"
				:is="field.fieldType"
				:value="thing[field.name]"
				@input="updateForm(field.name, $event)"
				v-bind="field">
			</component>

			<button v-if="newEntry" @click="save">Create</button>
			<button v-else @click="save">Update</button>
		</template>
	</div>
	`,
};

const tosDataApp = {
  mixins: [dataApp],
  data: () => ({
    fields: [
      {
        name: "name",
        placeholder: "name",
        fieldType: "my-text",
        required: true,
      },
      { name: "text", placeholder: "textarea", fieldType: "my-text-area" },
    ],
    initial: { name: "", text: "" },
    type: "tos",
    typeName: "Terms of Service",
  }),
};

const permissionDataApp = {
  mixins: [dataApp],
  data: () => ({
    fields: [
      {
        name: "name",
        placeholder: "name",
        fieldType: "my-text",
        required: true,
      },
    ],
    initial: { name: "" },
    type: "permission",
    typeName: "Permission",
  }),
};

const listApp = {
  data: () => ({
    loading: true,
    rows: [],
    searchInput: "",
    url: "",
    searchKey: "",
    title: "",
    displayedProps: ["id"],
    canCreate: false,
    page: 1,
    pages: 1,
  }),
  watch: {
    page: function () {
      if (this.page === "") {
        return;
      }
      this.refresh();
    },
  },
  methods: {
    refresh() {
      this.loading = true;
      const searchQuery = new URLSearchParams();

      if (this.searchInput.length) {
        searchQuery.set(this.searchKey, this.searchInput);
      }

      searchQuery.set("page", this.page);

      const searchQueryString = searchQuery.toString();

      authFetch(
        `${AUTH_URL}${this.url}${
          searchQueryString ? "?" + searchQueryString : ""
        }`
      ).then((rows) => {
        if (rows.pages !== undefined) {
          this.rows = rows.items;
          this.pages = rows.pages;
        } else {
          this.rows = rows;
        }

        this.loading = false;
      });
    },
  },
  mounted: function () {
    this.refresh();
  },
  template: `
	<div id="searchUsers" class="searchAndResults">
	
	<div class="listControls">
		<div class="searchForm right">
			<input v-model="searchInput" @keyup.enter="refresh" type="email" :placeholder="'search by ' + searchKey">
		</div>

		<div>
			<input min="1" :max="pages" v-model="page" type="number">
			<span>out of {{pages}}</span>
		</div>
	</div>

	<div id="searchUserResults" class="listContainer block">
		<div class="header">{{ title }}</div>
		<div class="list selectable" :style="{'grid-template-columns': 'repeat(' + displayedProps.length + ', auto)' }">
			<div v-if="loading">
				<div>Loading...</div>
			</div>
			<div v-else-if="rows.length === 0">
				<div>No Results</div>
			</div>
			<template v-else>
				<router-link v-for="data in rows" v-bind:key="data.id" :to="{ path: '' + data.id }" append>
					<div v-for="prop in displayedProps">{{ data[prop] }}</div>
				</router-link>
			</template>
		</div>
	</div>


	<router-link v-if="canCreate" :to="{ path: 'create' }" append>Create</router-link>

	</div>
	`,
};

const userStatsApp = {
  data: () => ({
    loading: true,
    rows: [],
    fromInput: "",
    toInput: "",
    url: "/user",
    title: "User Stats",
    displayedProps: ["name", "email", "created"],
  }),
  methods: {
    refresh() {
      const searchQuery = new URLSearchParams();

      function unitTimestamp(date) {
        return parseInt((new Date(date).getTime() / 1000).toFixed(0));
      }

      if (this.fromInput.length) {
        searchQuery.set("from", unitTimestamp(new Date(this.fromInput)));
      }

      if (this.toInput.length) {
        searchQuery.set("to", unitTimestamp(new Date(this.toInput)));
      }

      const searchQueryString = searchQuery.toString();

      authFetch(
        `${AUTH_URL}${this.url}${
          searchQueryString ? "?" + searchQueryString : ""
        }`
      ).then((rows) => {
        this.rows = rows;
        this.loading = false;
      });
    },
    exportToCSV() {
      let csvContent = "data:text/csv;charset=utf-8,";
      csvContent += this.displayedProps.join("\t");
      if (this.rows) {
        csvContent += "\n";
      }
      csvContent += this.rows
        .map((r) => this.displayedProps.map((p) => r[p]).join("\t"))
        .join("\n");
      window.open(encodeURI(csvContent));
    },
  },
  mounted: function () {
    this.refresh();
  },
  template: `
	<div id="searchUsers" class="searchAndResults">
	<div class="searchForm right">
		<label for="fromInput">From</label>
		<input id="fromInput" v-model="fromInput" type="date" @change="refresh">
		<label for="toInput">To</label>
		<input id="toInput" v-model="toInput" type="date" @change="refresh">
	</div>

	<button @click="exportToCSV">Export to CSV</button>

	<div id="searchUserResults" class="listContainer block">
		<div class="header">{{ title }}</div>
		<div class="list selectable" :style="{'grid-template-columns': 'repeat(' + displayedProps.length + ', auto)' }">
			<div v-if="loading">
				<div>Loading...</div>
			</div>
			<div v-else-if="rows.length === 0">
				<div>No Results</div>
			</div>
			<template v-else>
				<router-link v-for="data in rows" v-bind:key="data.id" :to="{ path: '' + data.id }" append>
					<div v-for="prop in displayedProps">{{ data[prop] }}</div>
				</router-link>
			</template>
		</div>
	</div>

	</div>
	`,
};

const userListApp = {
  mixins: [listApp],
  data: () => ({
    url: "/user",
    searchKey: "email",
    title: "Users",
    displayedProps: ["name", "email"],
    canCreate: true,
  }),
};

const serviceAccountListApp = {
  mixins: [listApp],
  data: () => ({
    url: "/service_account",
    searchKey: "name",
    title: "Service Accounts",
    displayedProps: ["name"],
    canCreate: true,
  }),
};

const groupListApp = {
  mixins: [listApp],
  data: () => ({
    url: "/group",
    searchKey: "name",
    title: "Groups",
    displayedProps: ["name"],
    canCreate: true,
  }),
};

const datasetListApp = {
  mixins: [listApp],
  data: () => ({
    url: "/dataset",
    searchKey: "name",
    title: "Datasets",
    displayedProps: ["name"],
    canCreate: true,
  }),
};

const tosListApp = {
  mixins: [listApp],
  data: () => ({
    url: "/tos",
    searchKey: "name",
    title: "Terms of Services",
    displayedProps: ["name"],
    canCreate: true,
  }),
};

const permissionListApp = {
  mixins: [listApp],
  data: () => ({
    url: "/permission",
    searchKey: "name",
    title: "Permissions",
    displayedProps: ["name"],
    canCreate: true,
  }),
};

const routes = [
  { path: "/user", name: "userList", component: userListApp },
  { path: "/user/:id", name: "userData", component: userDataApp },
  {
    path: "/service_account",
    name: "serviceAccountList",
    component: serviceAccountListApp,
  },
  {
    path: "/service_account/:id",
    name: "serviceAccountData",
    component: serviceAccountDataApp,
  },
  { path: "/group", name: "groupList", component: groupListApp },
  { path: "/group/:id", name: "groupData", component: groupDataApp },
  { path: "/dataset", name: "datasetList", component: datasetListApp },
  { path: "/dataset/:id", name: "datasetData", component: datasetDataApp },
  { path: "/tos", name: "tosList", component: tosListApp },
  { path: "/tos/:id", name: "tosData", component: tosDataApp },
  { path: "/permission", name: "permissionList", component: permissionListApp },
  {
    path: "/permission/:id",
    name: "permissionData",
    component: permissionDataApp,
  },
  { path: "/stats", name: "userStats", component: userStatsApp },
];

const router = new VueRouter({
  routes,
});

function wait(time) {
  return new Promise((f, r) => {
    setTimeout(f, time);
  });
}

const mainApp = new Vue({
  el: "#vueApp",
  router: router,
  data: {
    loggedInUser: null,
    networkResponse: null,
  },
  watch: {
    networkResponse: function (newMessage) {
      if (newMessage) {
        setTimeout(() => {
          this.networkResponse = null;
        }, 400 + 500);
      }
    },
  },
  methods: {
    login(force = false) {
      authFetch(
        `${AUTH_URL}/user/me${force ? "?middle_auth_token=null" : ""}`
      ).then((userData) => {
        this.loggedInUser = userData;
      });
    },
    logout() {
      authFetch(`${AUTH_URL}/logout`).then(() => {
        this.loggedInUser = null;
        localStorage.removeItem("auth_token");
        // window.location.reload(false);
      });
    },
  },
});

// returns a token to be used with services that use the given auth service
async function authorize(auth_url) {
  const plainURL = `${location.origin}${location.pathname}`.replace(
    /[^/]*$/,
    ""
  );

  const auth_popup = window.open(
    `${auth_url}?redirect=${encodeURI(plainURL + "redirect.html")}`
  );

  if (!auth_popup) {
    alert("Allow popups on this page to authenticate");
    return;
  }

  return new Promise((f, r) => {
    const tokenListener = (ev) => {
      if (ev.source === auth_popup) {
        auth_popup.close();
        window.removeEventListener("message", tokenListener);
        f(ev.data.token);
      }
    };

    window.addEventListener("message", tokenListener);
  });
}

function parseWWWAuthHeader(headerVal) {
  const tuples = headerVal
    .split("Bearer ")[1]
    .split(", ")
    .map((x) => x.split("="));
  const wwwAuthMap = {};

  for ([key, val] of tuples) {
    wwwAuthMap[key] = val.replace(/"/g, "");
  }

  return wwwAuthMap;
}

async function authFetch(input, init, retry = 1) {
  if (Array.isArray(input)) {
    return Promise.all(
      input.map((url) => {
        return authFetch(url, init, retry);
      })
    );
  }

  if (!input) {
    return fetch(input); // to keep the errors consistent
  }

  const token = localStorage.getItem("auth_token");

  options = init ? JSON.parse(JSON.stringify(init)) : {};

  options.headers = options.headers || new Headers();

  function addHeader(key, value) {
    if (options.headers instanceof Headers) {
      options.headers.append(key, value);
    } else {
      options.headers[key] = value;
    }
  }

  addHeader("X-Requested-With", "Fetch");

  if (token) {
    addHeader("Authorization", `Bearer ${token}`);
  }

  let res = await fetch(input, options);

  if ([400, 401].includes(res.status)) {
    const wwwAuth = res.headers.get("WWW-Authenticate");

    if (wwwAuth) {
      if (wwwAuth.startsWith("Bearer ")) {
        const wwwAuthMap = parseWWWAuthHeader(wwwAuth);

        if (!wwwAuthMap.error || wwwAuthMap.error === "invalid_token") {
          // missing or expired
          if (retry > 0) {
            return reauthenticate(wwwAuthMap.realm).then(() => {
              return authFetch(input, init, retry - 1);
            });
          }
        }

        throw new Error(
          `status ${res.status} auth error - ${wwwAuthMap.error} + " Reason: ${wwwAuthMap.error_description}`
        );
      }
    }
  }

  const httpMethod = (init && init.method) || "GET";

  const contentType = res.headers.get("content-type");

  const message = await (contentType === "application/json"
    ? res.json()
    : res.text());

  if (httpMethod !== "GET") {
    mainApp.networkResponse = {
      message: res.status === 200 ? "Success!" : message,
      error: res.status !== 200,
    };
  }

  if (res.status === 200) {
    return message;
  } else {
    throw new Error(`status: ${res.status} message: ${message}`);
  }
}

async function reauthenticate(realm) {
  const token = await authorize(realm);
  localStorage.setItem("auth_token", token);
}

if (localStorage.getItem("auth_token")) {
  mainApp.login();
}
