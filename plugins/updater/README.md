# updater

This is a REHex plugin for downloading/installing application updates. It must be configured to use an Ed25519-signed JSON Feed-based update feed by placing a `config.lua` in the plugin directory:

```lua
return {
    -- URL for the update feed.
    feed = "https://example.com/updates.json",

    -- Public key used to sign feed.
    pubkey = "<Ed25519 key>",

    -- Check for updates once a day while the application is running.
    interval_minutes = 24 * 60,

    -- Replace the running AppImage binary.
    -- method = "AppImage",

    -- Download and run Windows installer executable.
    -- method = "setup",

    -- Download the update to a place of the user's choosing.
    -- method = "download",
}

```

The JSON of the update feed should look something like the following:

```json
{
   "version" : "https://jsonfeed.org/version/1.1",
   "_signature" : "1e926f9cd6bc0d0a9460d09e724d6b00b722986ff730931091345b5025338eae569857f72858100d070f977cccbe47c090ea577b63e1718b71432a5e05e0e90e",
   "title" : "REHex Updates",
   "home_page_url" : "https://rehex.solemnwarning.net/",
   "feed_url" : "https://rehex.solemnwarning.net/updates/appimage-x64.json",
   "items" : [
      {
         "_sha256sum" : "47cd4d0f61180950a768d45814fc26849f3f3a665374be8fb855814acc1f4ca3",
         "_version" : "0.63.3",
         "content_text" : "<release notes go here>",
         "date_modified" : "2025-09-09T08:55:17Z",
         "date_published" : "2025-09-09T08:53:08Z",
         "id" : "291278924",
         "url" : "https://github.com/solemnwarning/rehex/releases/download/0.63.3/rehex-0.63.3-linux-generic-x86_64.AppImage"
      },
      {
         "_sha256sum" : "fa05ca1417756b8d36a6360f6de72163a4d8c83252b8d1eea3a6a223d4fd6dee",
         "_version" : "0.63.2",
         "content_text" : "<release notes go here>",
         "date_modified" : "2025-07-13T21:33:30Z",
         "date_published" : "2025-07-13T21:32:51Z",
         "id" : "272535777",
         "url" : "https://github.com/solemnwarning/rehex/releases/download/0.63.2/rehex-0.63.2-linux-generic-x86_64.AppImage"
      }
   ]
}
```

See the [JSON Feed](https://www.jsonfeed.org/version/1.1/) specification for the general structure of the update feed, with the following details specific to this application:

- The `url` of each item must be the package/distribution to download for this platform.
- The `_sha256sum` of each item must be the checksum of the file pointed to by `url`.
- The `_version` must be the version number, which will be compared against the "short" version of the running application.
- The third line of the file must be an Ed25519 signature of the feed exactly as it is encoded, minus this line.
