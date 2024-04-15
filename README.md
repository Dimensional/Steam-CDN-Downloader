For starters, this Repo is currently still in active development. There are 4 required files in order to make this work, 3 of them provided by this repo. 

You need to have NodeJS installed on your machine in order for this to be used. There are also user inputs that are required to use the files.

1st File: .env
 - This holds your Steam Login credentials. Instructions are found at the top of the JS files on what to set.

1st File: package.json.
 - This is holds the necessary libraries and other things in order for you to be able to use the scripts. It is recommended that in addition to installing nodejs, also install
 - PNPM, as this uses symbolic linking to decrease the amount of storage that get used by instlaling the dependencies.

2nd File: getallapps.js
 - Make sure you have the .env file created, as it holds your steam login. Do Not Share this file!!!
 - When it first runs with your login, it may request your Steam Guard TOTP.
 - Once it gets that and logs you in, it will generate a file called refreshToken.config.
   - This file is IMPORTANT. KEEP IT.
   - The RefreshToken file stores your login/session ID, identical to how Steam does it.
   - Do Not Share this file!!!
   - The JS files will use these to automatically log you in on subsequent logins.
 - After signing in, it calls out to Steam and gets a complete list of everything in your Steam Library.
 - This is formatted and filtered.
   - Apps in your library that are just configs, and thereby do not have a depot, are filtered out.
   - It will remove anything that isn't a proper depot, then save all of your apps and depot data to a single file.
   - If you enable Debugging by changing one variable, it will save each app data on separate JSON files. Makes for easier reading if needed.

3rd File: manifestDepotDownloader*.js (Currently on Version 3 of the Downloader. Version 4 is being worked on.)
 - This does the meat of the workd downloading the CDN Chunks and Manifest.
 - You must specify the app and depot by their ID.
 - By default, it looks at the Public Branch of your app's depot, and grabs the latest Manifest.
 - The Manifest is Steam's "Versioning" of apps, and the files generated in getallapps.js will only have the latest versions.
 - SteamDB.info can provide you with known previous versions of the Manifest IDs, but unknown can't be found.
 - Once it grabs the Manifest, it saves it as a raw binary file. This is compressed, so when decompressed, it generates a JSON list.
 - It can be further processed to get all of the file names for that Manifest. These are the files that get installed. Chunks don't need this additional processing.
 - Sometimes a chunk will appear more than once in the Manifest. By deduplicating, bandwidth will be saved.
 - Once every chunk has been parsed for processing, the downloader goes into effect.
   - The downloader will reach out to locate the appropriate CDN server that hosts the app's depot.
   - It will get a list of them, and pick from one to reach out to, creating a URL request.
   - The file is downloaded and stored in memory, where it is then processed for verification.
   - The chunk's filename is also the SHA checksum of the file, but not in it's downloaded state.
   - The chunk is decrypted using a symmetric key from the depot, and then unzipped. From there, it is then SHA'd, and that SHOULD match the file name.
   - If everything goes well, the file will then be saved to a pre-set folder. The size of the file will match the size listed in the Manifest.
   - Furthermore, there is a check where the downloader first checks to see if the chunk exists already and isn't corrupted.
     - If it's corrupted, deletes the file and redownloads.
     - If not corrupted, skips that file and goes to the next to check and/or download.

----------------------------

How Steam Depots work:
  Steam stores all of it's app files on CDN servers in Depot folders. These Depot folders go based on a Unique ID that is separate from App IDs.
  No 2 games will ever have the same Depot ID for their own separate data. If they use the same ID, then one game will 'own' that depot, and it is
  shared with the other game. This is the same with anything else on Steam, like DLC, Music, Tools, Servers, etc.

  Every CDN Chunk for that app's Depot will go into that folder, regardless of version. This means even updates will have their CDN Chunks stored there.
  As such, when downloading CDN Chunks for one version of the game or app, you may end up with a Chunk that is also used in another version, since updates
  don't change every file.
  CDN Chunks are the result of individual files for the app that get split up and compressed into chunks no bigger than 1MB in size. No chunk will store
  2 files, either as a whole in in parts.

  Given how the depot files are all shared between versions of the apps, known as Manifests and Branches, these chunks can be saved in a central location,
  and the manifest can be used to select which files to DAT.