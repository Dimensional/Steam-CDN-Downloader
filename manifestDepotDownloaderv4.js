/**
 * This is a repurposing of the BetaManifestDownloader example found within the stea-user module.
 * This script will take the App ID, Depot ID, and Branch Name, and use those to download the manifest,
 * which is saved in raw format before it is decompressed/decoded, and then further has the filenames
 * decoded, saving after each of those steps.
 * 
 * It then takes the names of the chunks, deduplicates them as some chunks are used more than once, and
 * finally downloads them from a Steam CDN server that holds the chunks.
 */

const APP_ID = 70;                        // The AppID of the app where you want to download a beta manifest
const DEPOT_ID = 1;                      // The ID of the depot whose manifest you want
const BRANCH_NAME = undefined;                // The name of the password-protected beta branch
const BRANCH_PASSWORD = undefined;        // The password for the branch
const MANIFEST_ID = undefined;	// Manifest ID needs to be in quotes to work, otherwise it should be undefined.

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

const SteamUser = require('steam-user'); // change to `require('steam-user')` if running outside of the examples directory
const LZMA = require('lzma');
const SteamCrypto = require('@doctormckay/steam-crypto'); // you'll need to add this to your package.json
const SteamTotp = require('steam-totp');
const StdLib = require('@doctormckay/stdlib');
const fs = require('fs');
const uniqs = require('uniqs');
const AdmZip = require('adm-zip');
const ByteBuffer = require('bytebuffer');
const ContentManifest = require('steam-user/components/content_manifest');

//const os = require('os');
//const { exec } = require('child_process');

const VZIP_HEADER = 0x5A56;
const VZIP_FOOTER = 0x767A;

let user = new SteamUser();

// Determine the operating system platform
//const platform = os.platform();

fs.access(STEAM_REFRESH_TOKEN, fs.constants.F_OK, (err) => {
	if (err) {
		console.log('Username and Password');
		user.logOn({
			accountName: STEAM_ACCOUNT_NAME,
			password: STEAM_ACCOUNT_PASSWORD,
			twoFactorCode: STEAM_ACCOUNT_2FA_SECRET ? SteamTotp.generateAuthCode(STEAM_ACCOUNT_2FA_SECRET) : undefined,
		});
		return;
	}
	let refresh = fs.readFileSync(STEAM_REFRESH_TOKEN, { encoding: 'utf8' });
	console.log('Using Refresh Token');
	//console.log(refresh);
	user.logOn({
		refreshToken: refresh
	});
});

user.on('loggedOn', async () => {
	console.log(`Logged on to Steam as ${user.steamID.steam3()}`);

	// First we need to download product info for the app so we can find the encrypted manifest id for the depot we want.
	// This will probably crash if we don't have a token for the app and it's private to only owners.
	// Though we need to own it anyway to get the depot decryption key.
	let branchID = BRANCH_NAME ? BRANCH_NAME : 'public';

	// Retrieves the App data.
	let appData = await user.getProductInfo([APP_ID], [], true);
	// Gets the name of the App from the data.
	let appName = appData.apps[APP_ID].appinfo.common.name;
	// Gets the Depots from the app.
	let depots = appData.apps[APP_ID].appinfo.depots;
	console.log(appName);
	//console.log(depots[DEPOT_ID]);
	//let branch = depots.branches[branchID];
	let ManifestId = MANIFEST_ID ? MANIFEST_ID : depots[DEPOT_ID].manifests[branchID].gid;

	/* if (!branch || !encryptedManifest || !encryptedManifest.encrypted_gid_2) {
		throw new Error(`Invalid branch name or no encrypted manifest available for "${BRANCH_NAME}" in depot ${DEPOT_ID}`);
	} */

	// console.log(`Encrypted manifest ID is ${encryptedManifest.encrypted_gid_2}`);
	// console.log(`Active build for branch ${BRANCH_NAME} is ${branch.buildid} (${branch.description})`);

	//console.log('Checking beta password');
	// let {keys} = await user.getAppBetaDecryptionKeys(APP_ID, BRANCH_PASSWORD);

	/* if (!keys[BRANCH_NAME]) {
		throw new Error(`Beta password incorrect for branch "${BRANCH_NAME}"`);
	} */

	// Decrypt the encrypted manifest id using the key we retrieved from the backend using the beta password.
	// Back in the day, the beta password *was* the key, but not so anymore. If we had encrypted_gid, that would be
	// the manifest id encrypted using the beta password.
	//let decryptedManifestId = SteamCrypto.symmetricDecryptECB(Buffer.from(encryptedManifest.encrypted_gid_2, 'hex'), keys[BRANCH_NAME]);
	//decryptedManifestId = decryptedManifestId.readBigUInt64LE(0).toString();
	//console.log(`Decrypted manifest ID is ${decryptedManifestId}`);

	// Now that we have the decrypted manifest id, we can download the manifest. getManifest will take care of retireving
	// the depot decryption key as well as the manifest request code. Retrieving the manifest request code is actually
	// the only reason we need to pass the branch name and password to getManifest,
	console.log('Downloading manifest');
	let manifestRaw = await getRawManifest1(APP_ID, DEPOT_ID, ManifestId, branchID, BRANCH_PASSWORD);
	let zippedBuffer = Buffer.from(manifestRaw.data);
	//console.log(JSON.stringify(unZippedManifest));

	// Forbidden Names must be Purged!!!!
	// Windows hates certain characters in file and folder names.
	let forbiddenCharsRegex = /[<>:"\/\\|?*\x00-\x1F]/g;
	appName = appName.replace(forbiddenCharsRegex, '');

	let filename = `${appName}_${DEPOT_ID}_manifest_${branchID}_${ManifestId}`;
	let dir = `./${appName}`;
	fs.mkdirSync(dir, {recursive: true});
	fs.writeFileSync(`${dir}/${filename}.bin`, zippedBuffer);

	// These are left over for testing each step. Can be deleted
	//const manifestObj = JSON.parse(manifestRaw);
	//const manifestString = manifestObj.manifest;
	//console.log(manifestRaw.manifest.buffer);

	// Below is where we grab the manifest buffer and saw the raw
	// manifest to a binary file. This is compressed and encoded.
	let unZippedManifest = await unzip(manifestRaw.data);
	//console.log(buffer);

	// Next, we are decompressing/decrypting the format to JSON for parsing.
	// This is without file names being decrypted. That is handled later.
	let manifestParsed = ContentManifest.parse(Buffer.from(unZippedManifest));
	//console.log(JSON.stringify(manifestParsed));
	//fs.writeFileSync(`./${appName}_manifest_${ManifestId}_encryptedFileNames.json`, JSON.stringify(manifestParsed, undefined, '\t'));

	// Some manifests may have the file names encrypted.
	// This isn't required for downloading chunks, but may be important
	// for record keeping, so being thurough anyways.
	if (manifestParsed.filenames_encrypted) {
		console.log('Filenames are Encrypted');
		fs.writeFileSync(`${dir}/${filename}_encryptedFileNames.json`, JSON.stringify(manifestParsed, undefined, '\t'));
		ContentManifest.decryptFilenames(manifestParsed, (await user.getDepotDecryptionKey(APP_ID, DEPOT_ID)).key);
		//console.log(JSON.stringify(manifestParsed));
	}
	fs.writeFileSync(`${dir}/${filename}.json`, JSON.stringify(manifestParsed, undefined, '\t'));

	// Next section is for parsing the chunk names and grabbing the chunks, saving to a folder.
	let chunks = [];
	manifestParsed.files.forEach(file => {
		file.chunks?.forEach(chunk => {
			//console.log(chunk.sha);
			chunks.push(chunk.sha);
		});
	});
	chunks = uniqs(chunks);
	let dirDL = `${dir}/${DEPOT_ID}/${branchID}/${ManifestId}`;
	fs.mkdirSync(dirDL, {recursive: true});
	fs.writeFileSync(`./${appName}/${DEPOT_ID}/${branchID}/${ManifestId}_chunks.json`, JSON.stringify(chunks, 4, '\t'));

	let {servers} = await user.getContentServers(APP_ID);
	let server = servers[Math.floor(Math.random() * servers.length)];

	// Disabled until symlinking in Windows can be figured out without Admin permissions.
	// Path to the target directory (the directory to which the link will point)
	//const targetPath = `./common/${DEPOT_ID}`;
	//fs.mkdirSync(targetPath, {recursive: true});

	for (let id in chunks) {

		// Check if the file exists AND isn't corrupted.
		let {key} = await user.getDepotDecryptionKey(APP_ID, DEPOT_ID);
		if (fs.existsSync(`${dirDL}/${chunks[id]}`)) {
			let openFile = fs.readFileSync(`${dirDL}/${chunks[id]}`);
			let corrupted = false;
			let result;

			try {
				let decryptedData = SteamCrypto.symmetricDecrypt(openFile, key);
				result = await unzip(decryptedData);
			} catch (err) {
				console.log('Corrupted file found or unzip error:', chunks[id], err.message);
				corrupted = true;
			}
			//console.log(StdLib.Hashing.sha1(result));
			if (result && !corrupted) {
				try {
					if (StdLib.Hashing.sha1(result) !== `${chunks[id]}`) {
						console.log('Checksum mismatch for', chunks[id]);
						corrupted = true;
					}
				} catch (hashError) {
					console.log('Error computing hash:', hashError.message);
            		corrupted = true;
           		}
			}
			if (corrupted) {
				try {
					await fs.promises.unlink(`${dirDL}/${chunks[id]}`);
					console.log(`File ${chunks[id]} deleted due to corruption or checksum mismatch.`);
				} catch (deleteError) {
					console.log('Error deleting file:', deleteError);
				}
			} else {
				// If the file is fine, continue to the next iteration
				continue;
			}
		}

		await downloadChunk1(APP_ID, DEPOT_ID, chunks[id], server, (err, data) => {
			let fileStream = fs.createWriteStream(`${dirDL}/${chunks[id]}`);
			fileStream.write(data);
		});
		
		/** Commented out until symlinking on Windows can be figured out
 		* without needing to change settings on the OS.
 		*/
		// if (platform === 'win32') {
		// 	createJunction(`${targetPath}/${chunks[id]}`, `${dirDL}/${chunks[id]}`);
		// } else {
		// 	createSymbolicLink(`${targetPath}/${chunks[id]}`, `${dirDL}/${chunks[id]}`);
		// }
	}

	user.logOff();
});

user.on('refreshToken', async (refreshToken) => {
	let filename = STEAM_REFRESH_TOKEN;
	fs.writeFileSync(filename, refreshToken);
});

function downloadChunk1(appID, depotID, chunkSha1, contentServer, callback) {
	if (typeof contentServer === 'function') {
		callback = contentServer;
		contentServer = null;
	}
	chunkSha1 = chunkSha1.toLowerCase();

	return StdLib.Promises.callbackPromise(['chunk'], callback, async (resolve, reject) => {
		if (!contentServer) {
			let {servers} = await user.getContentServers(appID);
			let contentServer = servers[Math.floor(Math.random() * servers.length)];
		}
		let urlBase = (contentServer.https_support == 'mandatory' ? 'https://' : 'http://') + contentServer.Host;
		//let urlBase = 'http://lancache.steamcontent.com';
		let vhost = contentServer.vhost || contentServer.Host;
		//let vhost = 'lancache.steamcontent.com';

		let {key} = await user.getDepotDecryptionKey(appID, depotID);

		let token = '';
		if (contentServer.usetokenauth == 1) {
			token = (await user.getCDNAuthToken(appID, depotID, vhost)).token;
		}

		download(`${urlBase}/depot/${depotID}/chunk/${chunkSha1}${token}`, vhost, async (err, res) => {
			if (err) {
				return reject(err);
			}

			if (res.type != 'complete') {
				return;
			}

			try {
				/** This step is used to verify the contents of the file are properly downloaded.
				 * It does this by decrypting the chunk using a Depot Decryption Key, where it
				 * then uses a custom decompression method. After it has done that, it gets a 
				 * sha1 checksum of the decompressed/decrypted data, and compares that to the file
				 * name. If they don't match, the file is not saved.
				 */
				let result = await unzip(SteamCrypto.symmetricDecrypt(res.data, key));
				//console.log(StdLib.Hashing.sha1(result));
				if (StdLib.Hashing.sha1(result) != chunkSha1) {
					return reject(new Error('Checksum mismatch'));
				}
				return resolve({chunk: res.data});
			} catch (ex) {
				return reject(ex);
			}
		});
	});
}

function download(url, hostHeader, destinationFilename, callback) {
	if (typeof destinationFilename === 'function') {
		callback = destinationFilename;
		destinationFilename = null;
	}

	let options = require('url').parse(url);
	options.method = 'GET';
	options.headers = {
		Host: hostHeader,
		Accept: 'text/html,*/*;q=0.9',
		'Accept-Encoding': 'gzip,identity,*;q=0',
		'Accept-Charset': 'ISO-8859-1,utf-8,*;q=0.7',
		'User-Agent': 'Valve/Steam HTTP Client 1.0'
	};

	let module = options.protocol.replace(':', '');
	let req = require(module).request(options, (res) => {
		if (res.statusCode != 200) {
			callback(new Error('HTTP error ' + res.statusCode));
			return;
		}

		res.setEncoding('binary'); // apparently using null just doesn't work... thanks node
		let stream = res;

		if (res.headers['content-encoding'] && res.headers['content-encoding'] == 'gzip') {
			stream = require('zlib').createGunzip();
			stream.setEncoding('binary');
			res.pipe(stream);
		}

		let totalSizeBytes = parseInt(res.headers['content-length'] || 0, 10);
		let receivedBytes = 0;
		let dataBuffer = Buffer.alloc(0);

		if (destinationFilename) {
			stream.pipe(require('fs').createWriteStream(destinationFilename));
		}

		stream.on('data', (chunk) => {
			if (typeof chunk === 'string') {
				chunk = Buffer.from(chunk, 'binary');
			}

			receivedBytes += chunk.length;

			if (!destinationFilename) {
				dataBuffer = Buffer.concat([dataBuffer, chunk]);
			}

			callback(null, {type: 'progress', receivedBytes: receivedBytes, totalSizeBytes: totalSizeBytes});
		});

		stream.on('end', () => {
			callback(null, {type: 'complete', data: dataBuffer});
			return;
		});
	});

	req.on('error', (err) => {
		callback(err);
	});

	req.end();
}

function unzip(data) {
	return new Promise((resolve, reject) => {
		// VZip or zip?
		if (data.readUInt16LE(0) != VZIP_HEADER) {
			// Standard zip
			let unzip = new AdmZip(data);
			return resolve(unzip.readFile(unzip.getEntries()[0]));
		} else {
			// VZip
			data = ByteBuffer.wrap(data, ByteBuffer.LITTLE_ENDIAN);

			data.skip(2); // header
			if (String.fromCharCode(data.readByte()) != 'a') {
				return reject(new Error('Expected VZip version \'a\''));
			}

			data.skip(4); // either a timestamp or a CRC; either way, forget it
			let properties = data.slice(data.offset, data.offset + 5).toBuffer();
			data.skip(5);

			let compressedData = data.slice(data.offset, data.limit - 10);
			data.skip(compressedData.remaining());

			let decompressedCrc = data.readUint32();
			let decompressedSize = data.readUint32();
			if (data.readUint16() != VZIP_FOOTER) {
				return reject(new Error('Didn\'t see expected VZip footer'));
			}

			let uncompressedSizeBuffer = Buffer.alloc(8);
			uncompressedSizeBuffer.writeUInt32LE(decompressedSize, 0);
			uncompressedSizeBuffer.writeUInt32LE(0, 4);

			LZMA.decompress(Buffer.concat([properties, uncompressedSizeBuffer, compressedData.toBuffer()]), (result, err) => {
				if (err) {
					return reject(err);
				}

				result = Buffer.from(result); // it's a byte array

				// Verify the result
				if (decompressedSize != result.length) {
					return reject(new Error('Decompressed size was not valid'));
				}

				if (StdLib.Hashing.crc32(result) != decompressedCrc) {
					return reject(new Error('CRC check failed on decompressed data'));
				}

				return resolve(result);
			});
		}
	});
}

/** Commented out until symlinking on Windows can be figured out
 * without needing to change settings on the OS.
 */

/*
function createSymbolicLink(targetPath, symlinkPath) {
    fs.symlink(targetPath, symlinkPath, 'file', (err) => {
        if (err) {
            console.error('Error creating symbolic link:', err);
            return;
        }
        //console.log('Symbolic link created successfully');
    });
}

// Function to create junction on Windows
function createJunction(targetPath, junctionPath) {
    exec(`mklink "${junctionPath}" "${targetPath}"`, (err, stdout, stderr) => {
        if (err) {
            console.error('Error creating junction:', err);
            return;
        }
        //console.log('Junction created successfully');
    });
} */

/**
 * Download and decompress a manifest, but don't parse it into a JavaScript object.
 * @param {int} appID
 * @param {int} depotID
 * @param {string} manifestID
 * @param {string} branchName - Now mandatory. Use 'public' for a the public build (i.e. not a beta)
 * @param {string} [branchPassword]
 * @param {function} [callback]
 */
function getRawManifest1(appID, depotID, manifestID, branchName, branchPassword, callback) {
	if (typeof branchName == 'function') {
		callback = branchName;
		branchName = null;
	}

	if (typeof branchPassword == 'function') {
		callback = branchPassword;
		branchPassword = null;
	}

	return StdLib.Promises.callbackPromise(['manifest'], callback, async (resolve, reject) => {
		let {servers} = await user.getContentServers(appID);
		let server = servers[Math.floor(Math.random() * servers.length)];

		/***Not worth flipping comments on the following 2 variables.
		 * Manifests have a required token that changes every 5 minutes.
		 * This causes a new file to be saved to LanCache instead of reusing the old one,
		 * needlessly increasing file storage if one is being used.
		 * */
		let urlBase = (server.https_support == 'mandatory' ? 'https://' : 'http://') + server.Host;
		//let urlBase = 'http://lancache.steamcontent.com';

		let vhost = server.vhost || server.Host;

		let token = '';
		if (server.usetokenauth == 1) {
			// Only request a CDN auth token if this server wants one.
			// I'm not sure that any servers use token auth anymore, but in case there's one out there that does,
			// we should still try.
			token = (await this.getCDNAuthToken(appID, depotID, vhost)).token;
		}

		if (!branchName) {
			this._warn(`No branch name was specified for app ${appID}, depot ${depotID}. Assuming "public".`);
			branchName = 'public';
		}

		let {requestCode} = await user.getManifestRequestCode(appID, depotID, manifestID, branchName, branchPassword);
		let manifestRequestCode = `/${requestCode}`;

		let manifestUrl = `${urlBase}/depot/${depotID}/manifest/${manifestID}/5${manifestRequestCode}${token}`;
		download(manifestUrl, vhost, async (err, res) => {
			if (err) {
				return reject(err);
			}

			if (res.type != 'complete') {
				return;
			}

			try {
				return resolve(res);
			} catch (ex) {
				return reject(ex);
			}
		});
	});
}
