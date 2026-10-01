package app.pwhs.blockads.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities

/** DNS servers supplied by the current underlying network, in its preferred order. */
internal object SystemDnsServers {
    fun current(context: Context): List<String> {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return emptyList()
        val active = manager.activeNetwork
        val network = if (active != null && isUsableNetwork(manager, active, false)) {
            active
        } else {
            // A VPN can become the default network. Use its validated physical
            // network rather than the DNS address exposed by our own tunnel.
            manager.allNetworks.firstOrNull { isUsableNetwork(manager, it, true) }
        } ?: return emptyList()
        return manager.getLinkProperties(network)?.dnsServers
            ?.mapNotNull { it.hostAddress?.substringBefore('%') }
            ?.filter { it.isNotBlank() && it != "0.0.0.0" && it != "::" }
            ?.distinct()
            ?: emptyList()
    }

    private fun isUsableNetwork(manager: ConnectivityManager, network: Network, requireValidated: Boolean): Boolean {
        val capabilities = manager.getNetworkCapabilities(network) ?: return false
        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            (!requireValidated || capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) &&
            !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }
}
