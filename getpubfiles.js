/**
 * This script gets the Manifest ID of a Workshop item. These are publicly visible,
 * however the CDN Chunks can not be downloaded without user access, as the base game
 * is also required.
 */

/** Change the workshop ID to match the workshop url you are looking at.
 * Example.
 * Workshop URL: https://steamcommunity.com/sharedfiles/filedetails/?id=3132351890
 * WorkshoID: 3132351890
 */
const workshopID = 3179290090;

const SteamUser = require('steam-user'); // change to `require('steam-user')` if running outside of the examples directory
const { exit } = require('process');

let user = new SteamUser();

user.logOn();
user.on('loggedOn', async () => {
	console.log(`Logged on to Steam as ${user.steamID.steam3()}`);
	await user.getPublishedFileDetails(workshopID, (err, files) => {
		if (err) {
			console.log('Danger Will Robinson!');
		}
		console.log('AppID and DepotID:', files[workshopID].consumer_appid);
		console.log('Manifest ID:', files[workshopID].hcontent_file);
		//console.log(JSON.stringify(files, undefined, '\t'));
		user.logOff();
		exit(0);
	});
});

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