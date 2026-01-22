return {
    -- URL for the update feed.
    feed = "https://rehex.solemnwarning.net/updates/windows-setup-x86.json",

    -- Public key
    pubkey = "791fa4ee6a9dc28905dcd64a15f98540c682ff096bfe98514acfadcbf21e4b03",

    -- Check for updates every 24 hours while the application is running.
    interval_minutes = 24 * 60,

    -- Download and run Windows installer executable.
    method = "setup"
}
