// returns a token to be used with services that use the given auth service
async function authorize(auth_url) {
	const oauth_uri = await fetch(`https://${auth_url}/authorize?redirect=${encodeURI(location.href.replace(/[^/]*$/, '') + 'redirect.html')}`, {
		credentials: 'include',
		headers: {
			'X-Requested-With': 'Fetch'
		}
	}).then((res) => {
		return res.text();
	});

	const auth_popup = window.open(oauth_uri);

	if (!auth_popup) {
		alert('Allow popups on this page to authenticate');
		return;
	}

	return new Promise((f, r) => {
		const tokenListener = (ev) => {
			if (ev.source === auth_popup) {
				auth_popup.close();
				window.removeEventListener("message", tokenListener);
				f(ev.data.token);
			}
		}
		
		window.addEventListener("message", tokenListener);
	});
}

function parseWWWAuthHeader(headerVal) {
	const tuples = headerVal.split('Bearer ')[1].split(', ').map((x) => x.split('='));
	const wwwAuthMap = {};

	for ([key, val] of tuples) {
		wwwAuthMap[key] = val.replace(/"/g, "");
	}

	return wwwAuthMap;
}

function authFetch(input, init, retry = 1) {
	if (!input) {
		return fetch(input); // to keep the errors consistent
	}

	const token = localStorage.getItem('auth_token');

	options = init ? JSON.parse(JSON.stringify(init)) : {};

	options.headers = options.headers || new Headers();

	function addHeader(key, value) {
		if (options.headers instanceof Headers) {
			options.headers.append(key, value);
		} else {
			options.headers[key] = value;
		}
	}

	addHeader('X-Requested-With', 'Fetch');
	
	if (token) {
		addHeader('Authorization', `Bearer ${token}`);
	}

	return fetch(input, options).then((res) => {
		if ([400, 401].includes(res.status)) {
			const wwwAuth = res.headers.get('WWW-Authenticate');

			if (wwwAuth) {
				if (wwwAuth.startsWith('Bearer ')) {
					const wwwAuthMap = parseWWWAuthHeader(wwwAuth);

					if (!wwwAuthMap.error || wwwAuthMap.error === 'invalid_token') {
						// missing or expired
						if (retry > 0) {
							return reauthenticate(wwwAuthMap.realm).then(() => {
								return authFetch(input, init, retry - 1);
							});
						}
					}

					throw new Error(`status ${res.status} auth error - ${wwwAuthMap.error} + " Reason: ${wwwAuthMap.error_description}`);
				}
			}
		}

		return res;
	});
}

async function reauthenticate(realm) {
	const token = await authorize(realm);
	localStorage.setItem('auth_token', token);
}

const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');

let availableGroups = null;

const refreshAvailableGroups = () => {
	return new Promise((f, r) => {
		authFetch(`${AUTH_URL}/group`).then((res) => {
			return res.json();
		}).then((res) => {
			availableGroups = res;

			addGroupSelect.innerHTML = "";

			for (let group of res) {
				const optionEl = document.createElement('option');
				optionEl.value = group.id;
				optionEl.innerHTML = group.name;

				addGroupSelect.appendChild(optionEl);
			}

			f();
		});
	})
};

const login = () => {
	authFetch(`${AUTH_URL}/test`).then((res) => {
		return res.json();
	}).then((userData) => {
		document.body.classList.toggle('loggedIn', true);
		document.body.classList.toggle('isAdmin', userData.admin);

		document.getElementById('email').innerHTML = `${userData.email} (${JSON.stringify(userData.permissions)})`;

		refreshAvailableGroups();
	});
};

loginBtn.addEventListener('click', login);

logoutBtn.addEventListener('click', () => {
	authFetch(`${AUTH_URL}/logout`).then(() => {
		localStorage.removeItem('auth_token');
		window.location.reload(false);
	});
});

let selectedUserId = null;

let selectedUser = null;

const searchBtn = document.getElementById('searchBtn');
const getUserInput = document.getElementById('getUserInput');

const refreshSelectedUser = () => {
	if (selectedUserId === null) {
		return;
	}

	authFetch(`${AUTH_URL}/user/${selectedUserId}`).then((res) => {
		return res.json();
	}).then((res) => {
		selectedUser = res;

		otherUserDataEl.querySelector('.username').innerHTML = res.username;
		otherUserDataEl.querySelector('.email').innerHTML = res.email;

		const selectedUsersGroups = otherUserDataEl.querySelector('.groups');
		
		selectedUsersGroups.innerHTML = "";

		for (let group of selectedUser.groups) {
			const groupEl = document.createElement('div');
			groupEl.innerHTML = group;

			const deleteGroupEl = document.createElement('div');
			deleteGroupEl.className = "deleteRow";

			deleteGroupEl.addEventListener('click', () => {
				for (let {id, name} of availableGroups) {
					if (name === group) {
						authFetch(`${AUTH_URL}/group/${id}/user/${selectedUser.id}`, {
							method: 'DELETE'
						}).then((res) => {
							refreshSelectedUser();
						});
					}
				}
			});

			selectedUsersGroups.appendChild(groupEl);
			selectedUsersGroups.appendChild(deleteGroupEl);
		}

		document.body.classList.toggle('selectedUser', true);
	});
};

const searchResultsEl = document.getElementById('searchResults');

searchBtn.addEventListener('click', () => {
	if (!getUserInput.value.length) {
		return;
	}

	authFetch(`${AUTH_URL}/user?email=${getUserInput.value}`).then((res) => {
		return res.json();
	}).then((rows) => {
		const searchResultsListEl = searchResultsEl.querySelector('.list');
		searchResultsListEl.innerHTML = "";

		// searchResultsListEl.classList.toggle('hasResult', true);

		if (rows.length === 0) {
			const rowEl = document.createElement('div');
			rowEl.innerHTML = 'No Results';
			searchResultsListEl.appendChild(rowEl);
		}

		for (let user of rows) {
			const rowEl = document.createElement('div');
			rowEl.innerHTML = `${user.email}`;
			searchResultsListEl.appendChild(rowEl);

			rowEl.addEventListener('click', () => {
				selectedUserId = user.id;
				refreshSelectedUser();
			});
		}
	});
});

const addGroupSelect = document.getElementById('addGroupSelect');
const addGroupBtn = document.getElementById('addGroupBtn');
const removeGroupBtn = document.getElementById('removeGroupBtn');

addGroupBtn.addEventListener('click', () => {
	if (!selectedUser) {
		return;
	}

	authFetch(`${AUTH_URL}/group/${addGroupSelect.value}/user`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			user_id: Number(selectedUser.id)
		})
	}).then((res) => {
		refreshSelectedUser();
	});
});

const myDataEl = document.getElementById('myData');
const otherUserDataEl = document.getElementById('otherUserData');

const AUTH_URL = 'https://dev.dynamicannotationframework.com/auth';

if (localStorage.getItem('auth_token')) {
	login();
}
