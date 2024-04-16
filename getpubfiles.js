/**
 * This downloads the whole library of apps, games, etc belonging to the user on Steam.
 * Sections can be uncommented to allow for saving various steps for troubleshooting and debugging.
 * This script was copied and repurposed from the betamanifestdownloader.js example file
 * found within the steam-user node module.
 */

/***
 * Create a file in this folder called .env
 * In this file, set 2 variables:
 *   STEAM_ACCOUNT_NAME='<your steam username>'
 *   STEAM_ACCOUNT_PASSWORD='<your steam password>'
 * These 2 variables are used to log in for the first time
 * if you haven't signed in yet and created a refresh token.
 */
require('dotenv').config()

const STEAM_ACCOUNT_NAME = process.env.STEAM_ACCOUNT_NAME ?? 'user';         // Username for your Steam account
const STEAM_ACCOUNT_PASSWORD = process.env.STEAM_ACCOUNT_PASSWORD ?? 'password'; // Password for your Steam account
const STEAM_ACCOUNT_2FA_SECRET = '';       // Your shared_secret if you have mobile authentication enabled, or blank to prompt for a code from stdin
const STEAM_REFRESH_TOKEN = './refreshToken.config';

/** Change the workshop ID to match the workshop url you are looking at.
 * Example.
 * Workshop URL: https://steamcommunity.com/sharedfiles/filedetails/?id=3132351890
 * WorkshoID: 3132351890
 */

const workshopID = 3132351890;

const SteamUser = require('steam-user'); // change to `require('steam-user')` if running outside of the examples directory
const SteamTotp = require('steam-totp');
const fs = require('fs');
const path = require('path');
const { exit } = require('process');

let dataSet = [];

const debugged = true;
const debugDir = './debug';

if (debugged) {
	try {
		fs.mkdirSync(debugDir, {recursive: true});
		console.log('Directory ${debugDir} created or already exists');
	} catch (error) {
		console.error(`Error creating directory ${path}:`, error);
	}
}

let user = new SteamUser();

// user.setOptions({
// 	//renewRefreshTokens: true,
// 	enablePicsCache: true
// });

// fs.access(STEAM_REFRESH_TOKEN, fs.constants.F_OK, (err) => {
// 	if (err) {
// 		console.log('Username and Password');
// 		user.logOn({
// 			accountName: STEAM_ACCOUNT_NAME,
// 			password: STEAM_ACCOUNT_PASSWORD,
// 			twoFactorCode: STEAM_ACCOUNT_2FA_SECRET ? SteamTotp.generateAuthCode(STEAM_ACCOUNT_2FA_SECRET) : undefined,
// 		});
// 		return;
// 	}
// 	let refresh = fs.readFileSync(STEAM_REFRESH_TOKEN, { encoding: 'utf8' });
// 	console.log('Using Refresh Token');
// 	//console.log(refresh);
// 	user.logOn({
// 		refreshToken: refresh,
// 	});
// });

user.logOn();
user.on('loggedOn', async () => {
	console.log(`Logged on to Steam as ${user.steamID.steam3()}`);
	await user.getPublishedFileDetails(workshopID, (err, files) => {
		if (err) {
			console.log('Danger Will Robinson!');
		}
		console.log(JSON.stringify(files[workshopID].hcontent_file, undefined, '\t'));
		user.logOff();
		exit(0);
	});
	//console.log(JSON.stringify(output));
});


// user.on('licenses', async function(licenses) {
// 	console.log('Got licenses.');
// 	if (debugged) {
// 		const licenseOut = path.join(debugDir, 'licenses.json');
// 		fs.writeFile(licenseOut, JSON.stringify(licenses, null, 4), 'utf8', function(error) {
// 			console.log(error || 'Successfully dumped our steam licenses to licenses.json');
// 		});
// 	}
// });

// user.on('ownershipCached', async () => {
// 	console.log('Ownership Cached');
	
// 	// Get all owned Apps.
// 	let output = user.getOwnedApps();
// 	fs.writeFileSync('apps.json', JSON.stringify(output, undefined, '\t'));

// 	// If you want to have every appID you own exported to a single JSON file,
// 	// then set debugged to true.
// 	// This file is a JSON list of every app ID in your library.
// 	// It contains only the App IDs, nothing else.
// 	if (debugged) {
// 		const appsOut = path.join(debugDir, 'apps.json');
// 		fs.writeFileSync(appsOut, JSON.stringify(output, null, 4), 'utf8', function(error) {
// 			console.log(error || 'Successfully dumped our steam licenses to licenses.json');
// 		});
// 	} 

// 	/* Uses the appIDs to get the product info. Product Info includes
// 	AppID
// 		Change Number
// 		Token
// 		AppInfo
// 			AppID again
// 			Common
// 				App Name
// 				App Type {DLC,Config,Tool,Game,Music,Application}
// 			Depots
// 				DepotID
// 					Config {oslist: windows,macos,linux}
// 					Manifest {public,etc}/ Encrypted Manifest for beta branches
// 					Some "depots" are not Objects. Exclude those.
// 				Branches
// 	*/
// 	// What we want is the 2nd AppID, since it's within the All Important AppInfo, the App Name, App Type, and Depots
// 	let result = await user.getProductInfo(output, [], true); // Passing true as the third argument automatically requests access tokens, which are required for some apps
// 	//console.log(result);
// 	//console.log('Got app info, writing to files');

// 	for (let appid in result.apps) {
		
// 		// Enables writing the appinfo object contents to separate files.
// 		// See above to understand what is in AppInfo
// 		// This writes the depot data for each app before filtering.
// 		if (debugged) {
// 			fs.mkdirSync(`${debugDir}/Apps_before`, {recursive: true});
// 			const fileName = `${appid}.json`;
// 			const AppsDirOut = path.join(debugDir, 'Apps_before', fileName);
// 			fs.writeFileSync(AppsDirOut, JSON.stringify(result.apps[appid].appinfo, null, '\t'));
// 		}

// 		/* Removal of any apps that are just configs or do not have any config type, such as
// 		*	AppId = 5: Engine.GoldSource, no type
// 		*	AppId = 7: Steam Client, config type
// 		*	We are only wanting DLC, Tools, Games, Music, Betas, Demos and Applications 
// 		*/ 
// 		if (!result.apps[appid].appinfo.common?.type || result.apps[appid].appinfo.common?.type == 'Config' || result.apps[appid].appinfo.common?.type == 'config') {
// 			delete result.apps[appid];
// 			continue;
// 		}
// 		// Now we only want those that have depots, since those are what we need to get manifests
// 		// and subsequently the chunks.
// 		if (!result.apps[appid].appinfo?.depots) {
// 			delete result.apps[appid];
// 			continue;
// 		}
		
// 		// This removes any depot item that isn't an object. These are things that do not include a manifest
// 		// which are their own object.
// 		for (let depots in result.apps[appid].appinfo?.depots) {
// 			if (typeof result.apps[appid].appinfo.depots[depots] !== 'object') {
// 				delete result.apps[appid].appinfo.depots[depots];
// 				continue
// 			}
// 			if (typeof result.apps[appid].appinfo.depots[depots].depotfromapp === 'string') {
// 				let numericPart = result.apps[appid].appinfo.depots[depots].depotfromapp.match(/\d+/);
// 				if (numericPart && output.includes(parseInt(numericPart[0]))) {
// 					delete result.apps[appid].appinfo.depots[depots];
// 					continue
// 				}
// 			}
// 		}

// 		// Tolld you we wanted these. :D
// 		const entry = {
// 			appid: appid,
// 			name: result.apps[appid].appinfo.common.name,
// 			type: result.apps[appid].appinfo.common.type,
// 			depots: result.apps[appid].appinfo.depots
// 		};
// 		dataSet.push(entry);
// 		if (debugged) {
// 			// Forbidden Names must be Purged!!!!
// 			// Windows hates certain characters in file and folder names.
// 			let appName = result.apps[appid].appinfo.common.name;
// 			let forbiddenCharsRegex = /[<>:"\/\\|?*\x00-\x1F]/g;
// 			appName = appName.replace(forbiddenCharsRegex, '');
			
// 			fs.mkdirSync(`${debugDir}/Apps_After`, {recursive: true});
// 			const fileName = `${appName}_${appid}.json`;
// 			const AppsDirOut = path.join(debugDir, 'Apps_After', fileName);
// 			fs.writeFileSync(AppsDirOut, JSON.stringify(result.apps[appid].appinfo, null, '\t'));
// 		}

// 	}
	
// 	// This will save every app and their respective depot information after records are deduplicated.
// 	fs.writeFileSync('./data.json', JSON.stringify(dataSet, undefined, '\t'));

// 	user.logOff();
// 	exit(0);
// });

// user.on('debug-traffic-outgoing', function(outputBuffer, header) {
// 	console.log('Header: ', header);
// 	console.log('Buffer: ', outputBuffer);
// });

// user.on('debug-traffic-incoming', function(buffer, eMsg) {
// 	console.log('Buffer: ', buffer);
// 	console.log('eMsg: ', eMsg);
// });

// user.on('debug', function(msg) {
// 	console.log(msg);
// });user.on('debug-traffic-incoming', function(buffer, eMsg) {
// 	console.log('Buffer: ', buffer);
// 	console.log('eMsg: ', eMsg);
// });

// user.on('debug', function(msg) {
// 	console.log(msg);
// });


/** The Refresh token is generated upon first login.
 * This detects when it is created and saves the file
 * for reuse. A real godsend for logging in, since you
 * don't have to type your password or SteamGuard token
 * every time, causing rate limits.
 **** DO NOT SHARE YOUR TOKEN!! ******
 */
user.on('refreshToken', async (refreshToken) => {
	let filename = STEAM_REFRESH_TOKEN;
	fs.writeFileSync(filename, refreshToken);
});