package app.pwhs.blockads.service

import org.junit.Assert.assertEquals
import org.junit.Test

class IptablesManagerTest {
    @Test
    fun sharedResolverIsExcludedOnlyWhenAppsAreWhitelisted() {
        assertEquals(listOf(10538), IptablesManager.excludedDnsUids(10538, emptyList()))
        assertEquals(
            listOf(10538, 10515, 0, 1000, 1051),
            IptablesManager.excludedDnsUids(10538, listOf(10515, 10515))
        )
    }
}
