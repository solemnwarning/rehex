return {
    -- URL for the update feed.
    feed = "https://rehex.solemnwarning.net/updates/appimage-x86.json",

    -- Public key
    pubkey = "92a0c67c346f141e2497bac5a37b8ec1217f5527d478a45264304afef3185101",

    -- Check for updates every 24 hours while the application is running.
    interval_minutes = 24 * 60,

    -- Replace the running AppImage binary.
    method = "AppImage",
}
