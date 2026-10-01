package app.pwhs.blockads.service

import android.content.Context
import com.topjohnwu.superuser.Shell
import timber.log.Timber

/**
 * Manages iptables rules for Root/Proxy mode.
 * Redirects all outbound DNS traffic (port 53 UDP/TCP) to the local
 * Go engine at 127.0.0.1:15353, excluding this app's own UID to prevent
 * infinite redirect loops.
 *
 * Uses a custom chain (BLOCKADS_DNS) for clean setup/teardown.
 *
 * Architecture:
 * - nat table:    REDIRECT port 53 → 15353 (DNS interception)
 * - filter table: optional DROP port 853
 * - settings: temporarily disable Android Private DNS only without app exclusions
 */
object IptablesManager {

    private const val CHAIN = "BLOCKADS_DNS"
    private const val CHAIN_FILTER = "BLOCKADS_DOT"
    private const val LOCAL_DNS_PORT = 15353
    private const val DNS_PREFS = "root_proxy_dns_state"
    private const val PREVIOUS_DNS_MODE = "previous_private_dns_mode"
    // Android's shared resolver sends DNS for multiple apps under a system UID.
    // Those packets cannot be assigned back to the requesting app at OUTPUT.
    // With app exclusions, passing them through is necessary to avoid filtering
    // excluded apps through another UID. Direct app-owned DNS is still filtered.
    private val SHARED_RESOLVER_UIDS = listOf(0, 1000, 1051)

    internal fun excludedDnsUids(appUid: Int, whitelistUids: Collection<Int>): List<Int> =
        (listOf(appUid) + whitelistUids +
            (if (whitelistUids.isNotEmpty()) SHARED_RESOLVER_UIDS else emptyList())).distinct()

    private fun savedDnsMode(context: Context) =
        context.getSharedPreferences(DNS_PREFS, Context.MODE_PRIVATE)

    /**
     * Ensure the cached libsu main shell actually has root.
     *
     * libsu creates the main shell once and caches it for the process
     * lifetime. If the first shell was created while the su daemon wasn't
     * ready yet (typical right after boot), a non-root `sh` gets cached and
     * every subsequent command silently runs without root — retries can
     * never succeed. Closing the poisoned shell forces libsu to build a
     * fresh one that attempts `su` again.
     */
    fun ensureRootShell(): Boolean {
        val cached = Shell.getCachedShell()
        if (cached != null && cached.isRoot) return true

        if (cached != null) {
            try {
                cached.close()
            } catch (e: Exception) {
                Timber.w(e, "Failed to close non-root shell")
            }
        }

        val fresh = Shell.getShell()
        Timber.d("Recreated libsu main shell, isRoot=${fresh.isRoot}")
        return fresh.isRoot
    }

    /**
     * Actively request root access. This will trigger the Magisk/KernelSU
     * permission prompt if it hasn't been granted yet.
     */
    fun isRootAvailable(): Boolean {
        return ensureRootShell()
    }

    /**
     * Apply iptables rules to redirect DNS traffic.
     *
     * @param context App context (used to get UID)
     * @param blockDoT If true, blocks DoT (port 853) to force DNS fallback to port 53
     * @param whitelistUids UIDs of excluded apps. Shared system DNS also passes
     *        through when this is nonempty because its originating app is unknown.
     * @return true if at least IPv4 rules succeeded
     */
    @Synchronized
    fun setupRules(
        context: Context,
        blockDoT: Boolean = false,
        whitelistUids: Collection<Int> = emptyList()
    ): Boolean {
        val uid = context.applicationInfo.uid
        val excludedUids = excludedDnsUids(uid, whitelistUids)
        Timber.d("Setting up iptables rules for UID=$uid, blockDoT=$blockDoT, excludedUids=$excludedUids")

        // Always teardown first (idempotent)
        teardownRules(context)
        if (isActive()) {
            Timber.e("Old DNS redirect is still active; refusing to stack rules")
            return false
        }

        // ══════════════════════════════════════════════════════════════
        // Step 0: With no app exclusions, disable Android Private DNS so
        // the root DNS redirect can see the system resolver's port 53 traffic.
        // With exclusions, shared resolver traffic must pass through anyway;
        // preserve the user's Private DNS setting and avoid a global change.
        // ══════════════════════════════════════════════════════════════
        if (whitelistUids.isEmpty()) {
            val currentMode = Shell.cmd("settings get global private_dns_mode").exec()
                .out.firstOrNull()?.trim().orEmpty()
            if (currentMode !in setOf("off", "opportunistic", "hostname")) {
                Timber.e("Unknown Private DNS mode; refusing to change global DNS setting")
                return false
            }
            if (currentMode != "off") {
                val saved = savedDnsMode(context)
                if (!saved.edit().putString(PREVIOUS_DNS_MODE, currentMode).commit()) {
                    Timber.e("Cannot preserve Private DNS setting; refusing root DNS setup")
                    return false
                }
                if (!Shell.cmd("settings put global private_dns_mode off").exec().isSuccess) {
                    saved.edit().remove(PREVIOUS_DNS_MODE).commit()
                    Timber.e("Cannot disable Private DNS for root DNS interception")
                    return false
                }
            }
        }

        // ══════════════════════════════════════════════════════════════
        // Step 1: nat table — REDIRECT port 53 → local engine
        //
        // NOTE: We run each iptables command individually so that a single
        // failure (e.g. chain already exists) doesn't abort the entire setup.
        // ══════════════════════════════════════════════════════════════
        val ipv4Commands = buildList {
            // Create chain (may fail if leftover — that's OK)
            add("iptables -t nat -N $CHAIN 2>/dev/null || true")
            // Skip our own app's traffic (prevents infinite loop)
            // System resolver DNS has no reliable originating app UID. When
            // exclusions exist, fail open for that shared path.
            for (wUid in excludedUids) {
                add("iptables -t nat -A $CHAIN -m owner --uid-owner $wUid -j RETURN")
            }
            // Redirect UDP DNS → local engine
            add("iptables -t nat -A $CHAIN -p udp --dport 53 -j REDIRECT --to-ports $LOCAL_DNS_PORT")
            // Redirect TCP DNS → local engine
            add("iptables -t nat -A $CHAIN -p tcp --dport 53 -j REDIRECT --to-ports $LOCAL_DNS_PORT")
            // Hook into OUTPUT chain
            add("iptables -t nat -A OUTPUT -j $CHAIN")

            if (blockDoT) {
                // filter table — DROP port 853 (DoT)
                add("iptables -t filter -N $CHAIN_FILTER 2>/dev/null || true")
                for (wUid in excludedUids) {
                    add("iptables -t filter -A $CHAIN_FILTER -m owner --uid-owner $wUid -j RETURN")
                }
                add("iptables -t filter -A $CHAIN_FILTER -p tcp --dport 853 -j REJECT")
                add("iptables -t filter -A OUTPUT -j $CHAIN_FILTER")
            }
        }

        var ipv4Success = true
        for (cmd in ipv4Commands) {
            val result = Shell.cmd(cmd).exec()
            if (!result.isSuccess) {
                Timber.e("IPv4 iptables cmd FAILED: [$cmd] err=${result.err} out=${result.out}")
                ipv4Success = false
                // Don't break — continue applying remaining rules so partial state is maximised
            }
        }

        if (ipv4Success) {
            Timber.d("IPv4 iptables setup SUCCESS")
        } else {
            Timber.e("IPv4 iptables setup had failures (see individual logs above)")
        }

        // ══════════════════════════════════════════════════════════════
        // IPv6 — try independently, many Android kernels lack ip6tables nat
        // ══════════════════════════════════════════════════════════════
        val ipv6Commands = buildList {
            add("ip6tables -t nat -N $CHAIN 2>/dev/null || true")
            for (wUid in excludedUids) {
                add("ip6tables -t nat -A $CHAIN -m owner --uid-owner $wUid -j RETURN")
            }
            add("ip6tables -t nat -A $CHAIN -p udp --dport 53 -j REDIRECT --to-ports $LOCAL_DNS_PORT")
            add("ip6tables -t nat -A $CHAIN -p tcp --dport 53 -j REDIRECT --to-ports $LOCAL_DNS_PORT")
            add("ip6tables -t nat -A OUTPUT -j $CHAIN")

            if (blockDoT) {
                add("ip6tables -t filter -N $CHAIN_FILTER 2>/dev/null || true")
                for (wUid in excludedUids) {
                    add("ip6tables -t filter -A $CHAIN_FILTER -m owner --uid-owner $wUid -j RETURN")
                }
                add("ip6tables -t filter -A $CHAIN_FILTER -p tcp --dport 853 -j REJECT")
                add("ip6tables -t filter -A OUTPUT -j $CHAIN_FILTER")
            }
        }

        for (cmd in ipv6Commands) {
            val result = Shell.cmd(cmd).exec()
            if (!result.isSuccess) {
                Timber.w("IPv6 ip6tables cmd FAILED (ignoring): [$cmd] err=${result.err}")
            }
        }

        // Verify rules are actually in place
        val verified = isActive()
        if (verified) {
            Timber.d("iptables rules verified active")
        } else {
            Timber.e("iptables rules NOT active after setup — root may have been denied")
        }

        if (!ipv4Success || !verified) {
            // Never leave a partially installed redirect after startup fails.
            teardownRules(context)
            return false
        }
        return true
    }

    /**
     * Remove all BlockAds iptables rules and restore Private DNS.
     * Safe to call multiple times. Uses 2>/dev/null to suppress errors.
     */
    @Synchronized
    fun teardownRules(context: Context): Boolean {
        val commands = listOf(
            // IPv4 nat chain
            "while iptables -t nat -C OUTPUT -j $CHAIN 2>/dev/null; do iptables -t nat -D OUTPUT -j $CHAIN 2>/dev/null || break; done",
            "iptables -t nat -F $CHAIN 2>/dev/null",
            "iptables -t nat -X $CHAIN 2>/dev/null",
            // IPv4 filter chain (DoT blocking)
            "while iptables -t filter -C OUTPUT -j $CHAIN_FILTER 2>/dev/null; do iptables -t filter -D OUTPUT -j $CHAIN_FILTER 2>/dev/null || break; done",
            "iptables -t filter -F $CHAIN_FILTER 2>/dev/null",
            "iptables -t filter -X $CHAIN_FILTER 2>/dev/null",
            // IPv6 nat chain
            "while ip6tables -t nat -C OUTPUT -j $CHAIN 2>/dev/null; do ip6tables -t nat -D OUTPUT -j $CHAIN 2>/dev/null || break; done",
            "ip6tables -t nat -F $CHAIN 2>/dev/null",
            "ip6tables -t nat -X $CHAIN 2>/dev/null",
            // IPv6 filter chain (DoT blocking)
            "while ip6tables -t filter -C OUTPUT -j $CHAIN_FILTER 2>/dev/null; do ip6tables -t filter -D OUTPUT -j $CHAIN_FILTER 2>/dev/null || break; done",
            "ip6tables -t filter -F $CHAIN_FILTER 2>/dev/null",
            "ip6tables -t filter -X $CHAIN_FILTER 2>/dev/null",
        )

        Shell.cmd(*commands.toTypedArray()).exec()
        val saved = savedDnsMode(context)
        val previousMode = saved.getString(PREVIOUS_DNS_MODE, null)
        if (previousMode != null) {
            val currentMode = Shell.cmd("settings get global private_dns_mode").exec()
                .out.firstOrNull()?.trim()
            // Respect a setting changed by the user while protection was active.
            if (currentMode != "off" || previousMode !in setOf("opportunistic", "hostname") ||
                Shell.cmd("settings put global private_dns_mode $previousMode").exec().isSuccess
            ) {
                saved.edit().remove(PREVIOUS_DNS_MODE).commit()
            } else {
                Timber.e("Failed to restore Private DNS mode; will retry on teardown")
            }
        }
        Timber.d("iptables teardown done")
        return true
    }

    /**
     * Check if our iptables rules are currently active.
     */
    fun isActive(): Boolean {
        val result = Shell.cmd(
            "iptables -t nat -L OUTPUT -n 2>/dev/null | grep $CHAIN"
        ).exec()
        return result.out.any { it.contains(CHAIN) }
    }
}
